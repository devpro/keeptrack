using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class VideoGameDetailPage(IPage page) : ReferenceableDetailPageBase(page, "RAWG")
{
    public override ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("cover$") });
}
