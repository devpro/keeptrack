using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Shared shape of every item's detail page (book, movie, TV show, video game, album, playlist, car, house, health profile, collectible, gear).
/// Each renders its title in an <c>&lt;input class="kt-title-input"&gt;</c>,
/// unique enough to locate without a <c>data-testid</c>, unlike the list pages' Add-form fields, plain <c>.form-control</c> inputs.
/// </summary>
public abstract partial class DetailPageBase(IPage page) : PageBase(page)
{
    [GeneratedRegex("(cover|poster)$")]
    private static partial Regex CoverRegex();

    public ILocator TitleInput => Page.Locator(".kt-title-input");

    /// <summary>
    /// The cover-image banner, when the page has one, every detail page's image ending its <c>alt</c> text in "cover" or "poster".
    /// A page without one (a playlist) never resolves it.
    /// </summary>
    public ILocator CoverImage => Page.GetByRole(AriaRole.Img, new PageGetByRoleOptions { NameRegex = CoverRegex() });

    /// <summary>
    /// The plain "Cover image URL" field of the five types not reference-linked (car, house, health profile, collectible, gear),
    /// <c>data-testid="image-url-input"</c>, since its label has no <c>for</c>/<c>id</c> association.
    /// The reference-linked types' equivalent (<c>CustomImageUrl</c>) is a separate field with no test id.
    /// </summary>
    public ILocator ImageUrlInput => Page.GetByTestId("image-url-input");

    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await Assertions.Expect(TitleInput).ToBeVisibleAsync();
    }

    /// <summary>
    /// Fills a detail-page field bound through <c>@onchange</c> (not <c>@bind</c>) and blurs it.
    /// <c>@onchange</c> listens for the native "change" event, which fires on blur once the value changed,
    /// not on Playwright's <c>FillAsync</c> alone, which dispatches only "input".
    /// </summary>
    public static async Task SetFieldAsync(ILocator input, string value)
    {
        await input.FillAsync(value);
        await input.BlurAsync();
    }
}
