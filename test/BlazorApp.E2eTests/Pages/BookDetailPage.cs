using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.E2eTests.Pages;

/// <summary>
/// <c>BookDetail.razor</c>'s fields are plain sibling <c>&lt;label&gt;</c>/<c>&lt;input&gt;</c> pairs with no
/// <c>for</c>/<c>id</c> association (and no wrapping <c>&lt;label&gt;</c> either), so <c>GetByLabel</c> can't
/// resolve them - there is no accessible-name link for Playwright to follow. <see cref="FieldInput"/> locates
/// by adjacent-sibling CSS instead, which needs no application markup change (the plan's own guidance is to
/// reach for <c>data-testid</c> only when role/label lookup is fragile; here it's not fragile, it structurally
/// can't apply at all, and this CSS approach needs no such change).
/// </summary>
public class BookDetailPage(IPage page) : PageBase(page)
{
    public async Task<BookDetailPage> WaitForReadyAsync()
    {
        await WaitForLoadingToResolveAsync(Page);
        await Assertions.Expect(Page.Locator(".kt-title-input")).ToBeVisibleAsync();
        return this;
    }

    public ILocator TitleInput => Page.Locator(".kt-title-input");

    public ILocator FieldInput(string label) => Page.Locator($"label.form-label:text-is('{label}') + input");

    public ILocator RefreshReferenceButton => Page.Locator("button.kt-icon-btn");

    public ILocator ReferenceToast => Page.Locator(".kt-inline-toast");

    public ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("cover$") });

    public async Task SetFieldAsync(string label, string value)
    {
        var input = FieldInput(label);
        await input.FillAsync(value);
        await input.BlurAsync();
    }

    public async Task ClickCheckReferenceMatchAsync()
    {
        await RefreshReferenceButton.ClickAsync();
        await Assertions.Expect(ReferenceToast).ToBeVisibleAsync();
    }
}
