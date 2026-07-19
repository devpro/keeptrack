using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape for the five detail pages that carry a reference-data concept (Book/Movie/TvShow/VideoGame/Album) -
/// all five render the exact same "check for reference match" icon button + toast,
/// and the exact same admin-only <c>InlineReferenceLinker</c> (search the real provider, pick a candidate, click "Link").
/// </summary>
public abstract partial class ReferenceableDetailPageBase(IPage page) : DetailPageBase(page)
{
    [GeneratedRegex("(cover|poster)$")]
    private static partial Regex CoverRegex();

    private ILocator RefreshReferenceButton => Page.Locator("button.kt-icon-btn");

    private ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    public ILocator CoverImage => Page.GetByRole(AriaRole.Img, new PageGetByRoleOptions { NameRegex = CoverRegex() });

    /// <summary>
    /// The non-admin, local-only-lookup "check for reference match" icon button - never calls a real provider, only used against pre-seeded/already-resolved data.
    /// </summary>
    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync();
    }

    /// <summary>
    /// The admin-only <c>InlineReferenceLinker</c>: a real, synchronous search against the actual external provider,
    /// then linking the first returned candidate.
    /// Only rendered while the item has no <c>ReferenceId</c> yet.
    /// The button is re-labeled rather than swapped out after the first search ("Search" -> "↻ Search again"),
    /// so this only ever needs to find the pre-search "Search" label - see <c>InlineReferenceLinker.razor</c>.
    /// A generous timeout is used for the search results since this is a genuine outbound network call, not a local lookup.
    /// </summary>
    public async Task SearchAndLinkFirstResultAsync()
    {
        var searchButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Search", Exact = true });
        var firstLinkButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Link" }).First;

        await searchButton.ClickAsync();
        await Assertions.Expect(firstLinkButton).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 20_000 });
        await firstLinkButton.ClickAsync();
    }
}
