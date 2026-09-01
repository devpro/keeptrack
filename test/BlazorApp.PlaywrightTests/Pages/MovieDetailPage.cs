using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public sealed class MovieDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    /// <summary>
    /// The year is what identifies a film, so supplying it after creation and re-checking is a journey worth
    /// driving through the UI - see <c>ReferenceMatchSmokeTest</c>. The input carries a test id for the same
    /// reason the video game one does: its label is not associated with it, so there is nothing accessible to
    /// locate it by.
    /// </summary>
    public ILocator YearInput => Page.GetByTestId("year-input");
}
