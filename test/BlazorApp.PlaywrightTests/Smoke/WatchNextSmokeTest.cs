using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Watch Next needs real, reference-linked, partially-watched data to assert anything meaningful (an empty
/// state is already covered by <c>NavigationSmokeTest</c>). Real-world airing status doesn't matter for the
/// "Current" state - <c>WatchNextService</c> only checks the tenant's own <c>State</c> field, not whether the
/// show is still airing in reality - so a long-finished, TMDB-stable show works and stays deterministic
/// (its episode list will never change between runs, unlike a currently-airing show's).
/// Uses different real titles than <see cref="TvShowSmokeTest"/>/<see cref="MovieSmokeTest"/> since every
/// smoke test shares the same e2e tenant and a fixed real-world title would otherwise collide.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class WatchNextSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private const string ShowTitle = "The Wire";
    private const string ShowYear = "2002";
    private const string MovieTitle = "Die Hard";
    private const string MovieYear = "1988";

    [Fact]
    public async Task WatchNext_ShowsConfirmedNextEpisodeAndWishlistedMovie()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();

        var showsList = await home.OpenTvShowsAsync();
        await showsList.ClickAddAsync();
        await showsList.FillAsync("title-input", ShowTitle);
        await showsList.FillAsync("year-input", ShowYear);
        await showsList.SaveNewAsync();

        var showDetail = new TvShowDetailPage(Page);
        await showDetail.WaitForReadyAsync();
        var showId = ExtractIdFromUrl(Page.Url);

        try
        {
            await showDetail.SearchAndLinkFirstResultAsync();
            await showDetail.SetStateAsync("Current");
            await showDetail.MarkFirstEpisodeWatchedAsync();

            var moviesList = await showDetail.OpenMoviesAsync();
            await moviesList.ClickAddAsync();
            await moviesList.FillAsync("title-input", MovieTitle);
            await moviesList.FillAsync("year-input", MovieYear);
            await moviesList.SaveNewAsync();

            var movieDetail = new MovieDetailPage(Page);
            await movieDetail.WaitForReadyAsync();
            var movieId = ExtractIdFromUrl(Page.Url);

            try
            {
                await Page.GetByRole(AriaRole.Button, new() { Name = "Watchlist" }).ClickAsync();

                var watchNext = await movieDetail.OpenWatchNextAsync();

                await Assertions.Expect(watchNext.Card(ShowTitle)).ToBeVisibleAsync();
                await Assertions.Expect(watchNext.CardBadge(ShowTitle)).ToContainTextAsync("E02");

                await watchNext.OpenMoviesTabAsync();
                await Assertions.Expect(watchNext.Card(MovieTitle)).ToBeVisibleAsync();
            }
            finally
            {
                await Fixture.DeleteItemAsync($"/api/movies/{movieId}");
            }
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/tv-shows/{showId}");
        }
    }
}
