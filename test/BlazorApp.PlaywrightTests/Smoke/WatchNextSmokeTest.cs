using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Runs alone, since Watch Next aggregates over the whole shared e2e tenant, and parallel classes creating and deleting shows and movies would race its assertions.
/// DisableParallelization gives it the quiet tenant it needs without slowing the rest of the suite down.
/// </summary>
[CollectionDefinition(nameof(WatchNextSmokeTest), DisableParallelization = true)]
public class WatchNextSmokeTestCollection;

/// <summary>
/// Watch Next needs real, reference-linked, partially-watched data to assert anything meaningful (an empty state is already covered by <c>NavigationSmokeTest</c>).
/// Real-world airing status doesn't matter for "Current", since <c>WatchNextService</c> checks the tenant's <c>State</c> field, so a long-finished show stays deterministic, its episode list never changing.
/// Its titles differ from <see cref="MovieSmokeTest"/>'s, since every smoke test shares the tenant and a fixed real-world title would collide.
/// See <see cref="WatchNextSmokeTestCollection"/> for why this class never runs in parallel with others.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
[Collection(nameof(WatchNextSmokeTest))]
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
        // the episode marked watched below needs no cleanup of its own: TvShowController.OnDeletedAsync cascades the delete to every episode of the show.
        TrackOpenItem("/api/tv-shows");

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
        TrackOpenItem("/api/movies");

        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Watchlist" }).ClickAsync();

        var watchNext = await movieDetail.OpenWatchNextAsync();

        await Assertions.Expect(watchNext.Card(ShowTitle)).ToBeVisibleAsync();
        await Assertions.Expect(watchNext.CardBadge(ShowTitle)).ToContainTextAsync("E02");

        await watchNext.OpenMoviesTabAsync();
        await Assertions.Expect(watchNext.Card(MovieTitle)).ToBeVisibleAsync();
    }
}
