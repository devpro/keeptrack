using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class BookDetailPage(IPage page) : ReferenceableDetailPageBase(page, "Open Library")
{
    public ILocator AuthorInput => Page.GetByTestId("author-input");

    public ILocator SeriesInput => Page.GetByTestId("series-input");

    public override ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("cover$") });

    public async Task SetFieldAsync(ILocator input, string value)
    {
        await input.FillAsync(value);
        await input.BlurAsync();
    }
}
