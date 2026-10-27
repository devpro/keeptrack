using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, long-finished TV show so linking exercises the real TMDB provider.
/// Its title differs from <see cref="WatchNextSmokeTest"/>'s, since both share the tenant, and a fixed real-world title, unlike the CRUD tests' GUID-suffixed ones, would collide.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class TvShowSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
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

        var detail = new TvShowDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/tv-shows");

        await detail.SearchAndLinkFirstResultAsync();

        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
    }
}
