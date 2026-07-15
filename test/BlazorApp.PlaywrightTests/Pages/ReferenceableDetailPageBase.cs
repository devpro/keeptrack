using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape for the five detail pages that carry a reference-data concept (Book/Movie/TvShow/VideoGame/
/// Album) - all five render the exact same "check for reference match" icon button + toast, and the exact
/// same admin-only <c>InlineReferenceLinker</c> (search the real provider, pick a candidate, click "Link").
/// <paramref name="providerName"/> is the display name <c>InlineReferenceLinker.razor</c> shows for
/// <see cref="Keeptrack.WebApi.Contracts.Dto.ReferenceItemType"/> ("TMDB", "Open Library", "RAWG", "Discogs").
/// </summary>
public abstract class ReferenceableDetailPageBase(IPage page, string providerName) : DetailPageBase(page)
{
    public ILocator RefreshReferenceButton => Page.Locator("button.kt-icon-btn");

    public ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    /// <summary>
    /// Alt-text suffix differs by domain ("... cover" for Book/VideoGame/Album, "... poster" for Movie/TvShow) -
    /// each concrete page supplies its own.
    /// </summary>
    public abstract ILocator CoverImage { get; }

    /// <summary>
    /// The non-admin, local-only-lookup "check for reference match" icon button - never calls a real
    /// provider, only used against pre-seeded/already-resolved data.
    /// </summary>
    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync();
    }

    /// <summary>
    /// The admin-only <c>InlineReferenceLinker</c>: a real, synchronous search against the actual external
    /// provider (TMDB/Open Library/RAWG/Discogs), then linking the first returned candidate. Only rendered
    /// while the item has no <c>ReferenceId</c> yet. A generous timeout is used for the search results
    /// since this is a genuine outbound network call, not a local lookup.
    /// </summary>
    public async Task SearchAndLinkFirstResultAsync()
    {
        var searchButton = Page.GetByRole(AriaRole.Button, new() { Name = $"Search {providerName} to link" });
        var firstLinkButton = Page.GetByRole(AriaRole.Button, new() { Name = "Link" }).First;

        await searchButton.ClickAsync();
        await Assertions.Expect(firstLinkButton).ToBeVisibleAsync(new() { Timeout = 20_000 });
        await firstLinkButton.ClickAsync();
    }
}
