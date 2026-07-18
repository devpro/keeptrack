using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The /add picker + one-shot forms. Type selection navigates via a ?type= query parameter (same
/// URL-state convention as the list pages), so <see cref="SelectTypeAsync"/> is a plain tile click.
/// </summary>
public class QuickAddPage(IPage page) : PageBase(page)
{
    public ILocator SaveButton => Page.GetByTestId("quickadd-save-button");

    public ILocator TitleInput => Page.GetByTestId("quickadd-title-input");

    /// <summary>
    /// The "‹ Choose a different type" link only renders once a known type is selected - a signal common
    /// to every type (media forms have a title input, record forms don't), so it's the one reliable
    /// "the form has loaded" wait target regardless of which type was picked.
    /// </summary>
    private ILocator BackLink => Page.Locator(".kt-quickadd-back");

    public async Task SelectTypeAsync(string type)
    {
        await Page.GetByTestId($"quickadd-type-{type}").ClickAsync();
        await Assertions.Expect(BackLink).ToBeVisibleAsync();
    }
}
