using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, long-finished TV show so linking exercises the actual TMDB provider - a different title
/// than <see cref="WatchNextSmokeTest"/> uses, since both share the same tenant and a fixed real-world
/// title (unlike the GUID-suffixed ones the plain CRUD tests use) would otherwise collide.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class TvShowSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    private const string Title = "Breaking Bad";
    private const string Year = "2008";

    [Fact]
    public async Task AddLinkAndDelete_TvShowThroughTheList()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenTvShowsAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", Title);
        await list.FillAsync("year-input", Year);
        await list.SaveNewAsync();

        // Creating an item navigates straight to its detail page.
        var detail = new TvShowDetailPage(Page);
        await detail.WaitForReadyAsync();
        var id = ExtractIdFromUrl(Page.Url);

        try
        {
            await detail.SearchAndLinkFirstResultAsync();

            await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/tv-shows/{id}");
        }
    }
}
