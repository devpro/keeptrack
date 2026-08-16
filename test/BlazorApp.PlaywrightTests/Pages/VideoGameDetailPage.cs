using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class VideoGameDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    /// <summary>
    /// The year field, which is what decides whether this game can be matched at all.
    /// It carries a <c>data-testid</c> because its label is a bare <c>&lt;label&gt;</c> with no <c>for</c>/<c>id</c> pairing, so there is nothing accessible to locate it by - the same minimal-testid exception the Add-form fields use.
    /// </summary>
    public ILocator YearInput => Page.GetByTestId("year-input");
}
