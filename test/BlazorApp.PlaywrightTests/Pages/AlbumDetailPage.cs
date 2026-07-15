using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public sealed class AlbumDetailPage(IPage page) : ReferenceableDetailPageBase(page, "Discogs")
{
    public ILocator ArtistInput => Page.GetByTestId("artist-input");
}
