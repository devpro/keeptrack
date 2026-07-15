using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape for every item's own detail page (Book/Movie/TvShow/VideoGame/Album/Playlist/Car/House) -
/// every one of them renders its title/name in an <c>&lt;input class="kt-title-input"&gt;</c>, a class
/// unique enough on the page to locate without any <c>data-testid</c> (unlike the list pages' Add-form
/// fields, which needed one since multiple plain <c>.form-control</c> inputs share no distinguishing class).
/// </summary>
public abstract class DetailPageBase(IPage page) : PageBase(page)
{
    public ILocator TitleInput => Page.Locator(".kt-title-input");

    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await Assertions.Expect(TitleInput).ToBeVisibleAsync();
    }
}
