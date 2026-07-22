using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape for every item's own detail page (Book/Movie/TvShow/VideoGame/Album/Playlist/Car/House/
/// HealthProfile/Collectible/Gear) - every one of them renders its title/name in an
/// <c>&lt;input class="kt-title-input"&gt;</c>, a class unique enough on the page to locate without any
/// <c>data-testid</c> (unlike the list pages' Add-form fields, which needed one since multiple plain
/// <c>.form-control</c> inputs share no distinguishing class).
/// </summary>
public abstract partial class DetailPageBase(IPage page) : PageBase(page)
{
    [GeneratedRegex("(cover|poster)$")]
    private static partial Regex CoverRegex();

    public ILocator TitleInput => Page.Locator(".kt-title-input");

    /// <summary>
    /// The cover-image banner, when the page has one - every detail page's own image element ends its
    /// <c>alt</c> text in "cover" (reference-hydrated types) or "poster" by the same convention. Not every
    /// subclass renders one (Playlist has no cover concept), so this simply never resolves on those.
    /// </summary>
    public ILocator CoverImage => Page.GetByRole(AriaRole.Img, new PageGetByRoleOptions { NameRegex = CoverRegex() });

    /// <summary>
    /// The plain "Cover image URL" field on the five non-reference-linked types (Car/House/HealthProfile/
    /// Collectible/Gear) - <c>data-testid="image-url-input"</c>, since the label/input pair has no
    /// <c>for</c>/<c>id</c> association. Book/Movie/TvShow/VideoGame/Album's reference-hydrated equivalent
    /// (<c>CustomImageUrl</c>) is a separate, not-yet-testid'd field, out of scope here.
    /// </summary>
    public ILocator ImageUrlInput => Page.GetByTestId("image-url-input");

    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await Assertions.Expect(TitleInput).ToBeVisibleAsync();
    }

    /// <summary>
    /// Fills a detail-page field bound via <c>@onchange</c> (not <c>@bind</c>) and blurs it - Blazor's
    /// <c>@onchange</c> listens for the native "change" event, which only fires on blur once the value has
    /// actually changed, not on Playwright's <c>FillAsync</c> alone (that only dispatches "input").
    /// </summary>
    public static async Task SetFieldAsync(ILocator input, string value)
    {
        await input.FillAsync(value);
        await input.BlurAsync();
    }
}
