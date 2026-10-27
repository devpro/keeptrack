using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class VideoGameDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    /// <summary>
    /// The year field, which decides whether this game can be matched at all.
    /// It carries a <c>data-testid</c>, since its label is a bare <c>&lt;label&gt;</c> with no <c>for</c>/<c>id</c> pairing, the minimal test-id exception of the Add-form fields.
    /// </summary>
    public ILocator YearInput => Page.GetByTestId("year-input");
}
