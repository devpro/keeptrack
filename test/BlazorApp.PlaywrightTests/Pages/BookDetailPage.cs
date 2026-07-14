using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// <c>BookDetail.razor</c>'s fields are plain sibling <c>&lt;label&gt;</c>/<c>&lt;input&gt;</c> pairs with no
/// <c>for</c>/<c>id</c> association (and no wrapping <c>&lt;label&gt;</c> either), so <c>GetByLabel</c>
/// structurally can't resolve them - confirmed against a real run (every fill silently timed out). Fields
/// this page object needs (title/author/series) got a minimal <c>data-testid</c> added to the application
/// markup instead, matching <c>todo-blazor</c>'s own convention for exactly this situation.
/// </summary>
public class BookDetailPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await Assertions.Expect(TitleInput).ToBeVisibleAsync();
    }

    public ILocator TitleInput => Page.GetByTestId("title-input");

    public ILocator AuthorInput => Page.GetByTestId("author-input");

    public ILocator SeriesInput => Page.GetByTestId("series-input");

    public ILocator RefreshReferenceButton => Page.Locator("button.kt-icon-btn");

    public ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    public ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("cover$") });

    public async Task SetFieldAsync(ILocator input, string value)
    {
        await input.FillAsync(value);
        await input.BlurAsync();
    }

    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync();
    }
}
