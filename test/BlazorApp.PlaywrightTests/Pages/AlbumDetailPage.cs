using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class AlbumDetailPage(IPage page) : ReferenceableDetailPageBase(page, "Discogs")
{
    public ILocator ArtistInput => Page.GetByTestId("artist-input");

    public override ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("cover$") });
}
