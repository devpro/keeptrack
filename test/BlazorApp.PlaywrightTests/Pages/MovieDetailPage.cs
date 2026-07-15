using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class MovieDetailPage(IPage page) : ReferenceableDetailPageBase(page, "TMDB")
{
    public override ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("poster$") });
}
