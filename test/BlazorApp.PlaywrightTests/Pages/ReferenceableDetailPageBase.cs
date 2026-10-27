using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape of the five reference-linked detail pages (book, movie, TV show, video game, album).
/// All five render the same "check for reference match" icon button and toast,
/// and the same admin-only <c>InlineReferenceLinker</c> (search the real provider, pick a candidate, click "Link").
/// <see cref="CoverImage"/> is inherited from <see cref="DetailPageBase"/>, shared with the other types.
/// </summary>
public abstract class ReferenceableDetailPageBase(IPage page) : DetailPageBase(page)
{
    /// <summary>
    /// Located by accessible name rather than by <c>.kt-icon-btn</c>.
    /// Once an item is linked an admin also sees the unlink button, which carries the same class,
    /// so the plain class selector resolves to two elements and Playwright refuses to click either.
    /// </summary>
    private ILocator RefreshReferenceButton => Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Check for reference match" });

    private ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    /// <summary>
    /// Deletes the item from its own page, the confirm click scoped to the modal, whose button shares the "Delete" name.
    /// Opening the confirmation is the first click after load, so it goes through <see cref="PageBase.ClickUntilAsync(ILocator, ILocator, int)"/>.
    /// </summary>
    public async Task DeleteItemAsync()
    {
        var confirm = Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete", Exact = true });
        await ClickUntilAsync(Page.Locator(".kt-page-header").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete", Exact = true }), confirm);
        await confirm.ClickAsync();
    }

    /// <summary>
    /// The non-admin "check for reference match" icon button.
    /// </summary>
    /// <remarks>
    /// All five domains escalate to the provider when nothing local answers, which lets an item created before its identity field was known be matched.
    /// The toast can then take as long as the provider, so the wait clears a healthy provider's slowest honest answer.
    /// Every provider client chains <c>AddStandardResilienceHandler</c> with its own total-request-timeout ceiling
    /// (30s for TMDB, RAWG and Discogs, 40s for the book providers, see <c>ProviderResilienceExtensions</c>).
    /// A transient failure spends retries up to that ceiling before returning.
    /// </remarks>
    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = ProviderCallTimeoutMs });
    }

    /// <summary>
    /// How long a "check for reference match" may take, since it reaches a provider (see <see cref="ClickCheckReferenceMatchAsync"/>).
    /// One full provider budget (40s, the book ceiling) plus margin covers any single leg exhausting its retries, and every healthy answer.
    /// Waiting through two failure budgets would only reach the same failure later, since the assertions after this one need a provider that answered.
    /// </summary>
    private const float ProviderCallTimeoutMs = 45_000;

    /// <summary>
    /// Drives an unlinked item all the way to linked, the way an admin does it.
    /// <para>
    /// It starts with the "check for reference match" button, which reveals the admin-only <c>InlineReferenceLinker</c>.
    /// Each detail page shows the panel only once a check comes back without a link (<c>ShowLinker</c>), never on an unlinked item alone.
    /// </para>
    /// <para>
    /// The check can succeed by itself, leaving nothing to search for and no panel.
    /// These smoke tests link fixed real titles, and a previous run's reference document is left in place (see the cleanup section of docs/testing.md),
    /// so from the second run the item links on the check alone.
    /// Both outcomes leave the item linked, which every caller asserts next.
    /// The panel's absence reliably signals the first outcome, since it renders for exactly "admin, and not linked", and the e2e identity is an admin.
    /// </para>
    /// <para>
    /// The button is relabelled rather than swapped after the first search ("Search" to "Search again"),
    /// so this finds only the pre-search "Search" label (see <c>InlineReferenceLinker.razor</c>).
    /// </para>
    /// <para>
    /// The wait for search results must exceed the server's worst case: each provider client's resilience ceiling (see <see cref="ClickCheckReferenceMatchAsync"/>).
    /// A shorter wait can time out on a search still in progress rather than a stuck one.
    /// A search is one provider leg, so it shares the check's <see cref="ProviderCallTimeoutMs"/>.
    /// </para>
    /// </summary>
    public async Task SearchAndLinkFirstResultAsync()
    {
        // Waits for the result toast, so the render that decides whether the panel appears has already been applied by the time the panel is looked for below.
        await ClickCheckReferenceMatchAsync();

        var searchButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Search", Exact = true });
        if (await searchButton.CountAsync() == 0)
        {
            return;
        }

        var firstLinkButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Link" }).First;

        await searchButton.ClickAsync();
        await Assertions.Expect(firstLinkButton).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = ProviderCallTimeoutMs });
        await firstLinkButton.ClickAsync();
    }
}
