using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape for the five detail pages that carry a reference-data concept (Book/Movie/TvShow/VideoGame/Album) -
/// all five render the exact same "check for reference match" icon button + toast,
/// and the exact same admin-only <c>InlineReferenceLinker</c> (search the real provider, pick a candidate, click "Link").
/// <see cref="CoverImage"/> is inherited from <see cref="DetailPageBase"/> - shared with the non-reference-linked types too.
/// </summary>
public abstract class ReferenceableDetailPageBase(IPage page) : DetailPageBase(page)
{
    private ILocator RefreshReferenceButton => Page.Locator("button.kt-icon-btn");

    private ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    /// <summary>
    /// The non-admin, local-only-lookup "check for reference match" icon button - never calls a real provider, only used against pre-seeded/already-resolved data.
    /// </summary>
    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync();
    }

    /// <summary>
    /// Drives an unlinked item all the way to linked, the way an admin does it.
    /// <para>
    /// It starts with the "check for reference match" button, because that is what now reveals the admin-only
    /// <c>InlineReferenceLinker</c>: the panel used to render on any unlinked item, and no longer does -
    /// each detail page gates it on a <c>_showLinker</c> flag that the check sets when it comes back without
    /// a link. Clicking straight through to "Search" is what this method used to do, and it now waits 30s for
    /// a button that is never rendered.
    /// </para>
    /// <para>
    /// That check is a local-only lookup (it never calls a provider) and it can succeed by itself, in which
    /// case there is nothing to search for and no panel: these smoke tests link fixed real titles, and the
    /// reference document a previous run created is deliberately left behind (see the testing section of
    /// CLAUDE.md), so from the second run onwards the item links on the check alone. Both outcomes leave the
    /// item linked, which is what every caller asserts next. The panel's absence is a reliable signal of the
    /// first outcome rather than a guess, because it is rendered for exactly "admin, and not linked" - and
    /// the e2e identity is always an admin.
    /// </para>
    /// <para>
    /// The button is re-labeled rather than swapped out after the first search ("Search" -> "Search again"),
    /// so this only ever needs to find the pre-search "Search" label - see <c>InlineReferenceLinker.razor</c>.
    /// </para>
    /// <para>
    /// The wait for search results must exceed the server's own worst case, not just be "generous": every
    /// provider client chains <c>AddStandardResilienceHandler</c> with a total-request-timeout ceiling of its
    /// own (30s default for TMDB/RAWG/Discogs, 40s for the book providers - see
    /// <c>ProviderResilienceExtensions</c>), and a transient failure genuinely spends retries up to that
    /// ceiling before the call gives up and returns. A client-side wait shorter than the longest of those
    /// ceilings can time out on a real, in-progress search rather than a stuck one - confirmed against a real
    /// run where the search was still visibly in progress when this assertion gave up at 20s.
    /// </para>
    /// </summary>
    public async Task SearchAndLinkFirstResultAsync()
    {
        // Waits for the result toast, so the render that decides whether the panel appears has already been
        // applied by the time the panel is looked for below.
        await ClickCheckReferenceMatchAsync();

        var searchButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Search", Exact = true });
        if (await searchButton.CountAsync() == 0)
        {
            return;
        }

        var firstLinkButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Link" }).First;

        await searchButton.ClickAsync();
        await Assertions.Expect(firstLinkButton).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 45_000 });
        await firstLinkButton.ClickAsync();
    }
}
