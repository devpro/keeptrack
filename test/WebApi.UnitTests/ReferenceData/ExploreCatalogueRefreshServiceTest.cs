using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The pass that materializes each provider's ranking into <c>explore_catalogue</c>: rank assignment across
/// provider pages, the staleness gate, the deliberate refusal to prune when a pass didn't complete, and the
/// bounded IMDb rating backfill.
/// </summary>
[Trait("Category", "UnitTests")]
public class ExploreCatalogueRefreshServiceTest
{
    private readonly Mock<ITmdbClient> _tmdbClient = new();
    private readonly FakeVideoGameReferenceClient _videoGameClient = FakeVideoGameReferenceClient.Empty();
    private readonly Mock<IOmdbClient> _omdbClient = new();
    private readonly Mock<IAppSettingRepository> _appSettingRepository = new();
    private readonly Mock<IExploreCatalogueRepository> _catalogueRepository = new();
    private readonly FakeOmdbCallBudget _omdbCallBudget = new();

    private readonly List<ExploreCatalogueEntryModel> _upserted = [];

    private ExploreCatalogueRefreshService CreateService()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string>());
        _catalogueRepository
            .Setup(r => r.UpsertManyAsync(It.IsAny<IReadOnlyList<ExploreCatalogueEntryModel>>()))
            .Callback((IReadOnlyList<ExploreCatalogueEntryModel> entries) => _upserted.AddRange(entries))
            .Returns(Task.CompletedTask);
        _catalogueRepository
            .Setup(r => r.FindMissingRatingAsync(
                It.IsAny<ExploreItemType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<int>()))
            .ReturnsAsync([]);
        var videoGameClients = new ReferenceClientRegistry<IVideoGameReferenceClient>([_videoGameClient], _videoGameClient.ProviderKey);
        return new(
            _tmdbClient.Object, videoGameClients, new ExploreRankings(videoGameClients), _omdbClient.Object, _omdbCallBudget,
            _appSettingRepository.Object, new RatingSourceOptions(videoGameClients), _catalogueRepository.Object,
            NullLogger<ExploreCatalogueRefreshService>.Instance);
    }

    /// <summary>
    /// Every ranking looks freshly built by default, so a test only has to make the one it cares about stale -
    /// otherwise the pass would walk all four and every test would need every provider stubbed.
    /// </summary>
    private void AllRankingsFresh()
    {
        _catalogueRepository
            .Setup(r => r.FindOldestRefreshedAtAsync(It.IsAny<ExploreItemType>(), It.IsAny<string>()))
            .ReturnsAsync(DateTime.UtcNow);
    }

    private void RankingIsStale(ExploreItemType type, string ranking) =>
        _catalogueRepository.Setup(r => r.FindOldestRefreshedAtAsync(type, ranking)).ReturnsAsync(DateTime.UtcNow.AddDays(-30));

    private static TmdbTopRatedItem Movie(string id, double rating) => new(id, $"Movie {id}", 1999, "synopsis", "http://img", rating);

    private static VideoGameTopRatedItem Game(string id, double? userRating, double? criticRating)
    {
        var ratings = new Dictionary<string, double>();
        if (userRating is not null) ratings[RatingSourceCatalog.Igdb] = userRating.Value;
        if (criticRating is not null) ratings[RatingSourceCatalog.IgdbCritic] = criticRating.Value;
        return new VideoGameTopRatedItem(id, $"Game {id}", 2010, "http://img", ratings);
    }

    private void TmdbPages(params IReadOnlyList<TmdbTopRatedItem>[] pages)
    {
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        for (var i = 0; i < pages.Length; i++)
        {
            var page = pages[i];
            _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(i + 1, It.IsAny<CancellationToken>())).ReturnsAsync(page);
        }
    }

    [Fact]
    public async Task RefreshAsync_RanksTitlesContinuouslyAcrossProviderPages()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.Movie, "tmdb");
        TmdbPages([Movie("a", 9.0), Movie("b", 8.9)], [Movie("c", 8.8)]);

        var result = await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // rank is the position in the whole ranking, not within a page - it is the read path's paging cursor,
        // so a per-page restart would make every page after the first re-serve the same titles.
        _upserted.Select(e => (e.ExternalId, e.Rank)).Should().Equal([("a", 1), ("b", 2), ("c", 3)]);
        result.EntriesRefreshed.Should().Be(3);
        result.RankingsRefreshed.Should().Be(1);
    }

    [Fact]
    public async Task RefreshAsync_StampsEveryEntryOfAPassIdentically_ThenPrunesWhatItDidNotRewrite()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.Movie, "tmdb");
        TmdbPages([Movie("a", 9.0), Movie("b", 8.9)]);

        await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // one shared timestamp is what lets the prune be a single "older than me" delete
        _upserted.Select(e => e.RefreshedAt).Distinct().Should().ContainSingle();
        _catalogueRepository.Verify(
            r => r.DeleteStaleAsync(ExploreItemType.Movie, "tmdb", _upserted[0].RefreshedAt), Times.Once);
    }

    [Fact]
    public async Task RefreshAsync_WhenTheProviderReturnsNothing_KeepsThePreviousCatalogue()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.Movie, "tmdb");
        TmdbPages(); // every page empty - an outage, a revoked key, a provider change

        var result = await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // pruning here would empty Explore for everyone until the next weekly pass. A week-old ranking is a
        // far better answer than none, so the prune only ever follows a pass that actually produced titles.
        _catalogueRepository.Verify(
            r => r.DeleteStaleAsync(It.IsAny<ExploreItemType>(), It.IsAny<string>(), It.IsAny<DateTime>()), Times.Never);
        result.EntriesRefreshed.Should().Be(0);
    }

    [Fact]
    public async Task RefreshAsync_SkipsARankingThatIsStillFresh()
    {
        AllRankingsFresh();

        var result = await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.RankingsRefreshed.Should().Be(0);
        _tmdbClient.Verify(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
        _videoGameClient.LastTopRatedOrdering.Should().BeNull();
    }

    [Fact]
    public async Task RefreshAsync_RebuildsARankingThatWasNeverBuilt()
    {
        AllRankingsFresh();
        _catalogueRepository.Setup(r => r.FindOldestRefreshedAtAsync(ExploreItemType.Movie, "tmdb")).ReturnsAsync((DateTime?)null);
        TmdbPages([Movie("a", 9.0)]);

        var result = await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.RankingsRefreshed.Should().Be(1);
    }

    [Fact]
    public async Task RefreshAsync_WithZeroStaleness_RebuildsEvenAJustRefreshedRanking()
    {
        AllRankingsFresh();
        TmdbPages([Movie("a", 9.0)]);
        _tmdbClient.Setup(c => c.GetTopRatedTvShowsAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);

        // what the admin's "sync now" passes - the force-it-now path
        var result = await CreateService().RefreshAsync(TimeSpan.Zero, TestContext.Current.CancellationToken);

        result.RankingsRefreshed.Should().Be(4, "movies, TV shows, and video games by each of the provider's two sources");
    }

    [Fact]
    public async Task RefreshAsync_StoresEveryScoreTheProviderReports_WhicheverOrderingTheListWasPulledIn()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.VideoGame, RatingSourceCatalog.IgdbCritic);
        _videoGameClient.TopRatedPages[1] = [Game("g1", 92, 96)];

        await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // a game provider puts every number it has on each listing entry, so storing all of them costs nothing
        // and means switching the admin's selected source never needs a provider call
        _upserted.Should().ContainSingle();
        _upserted[0].Ratings.Should().BeEquivalentTo(new Dictionary<string, double> { ["igdb"] = 92, ["igdbcritic"] = 96 });
    }

    [Fact]
    public async Task RefreshAsync_OmitsARatingTheListingDidNotCarry()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.VideoGame, RatingSourceCatalog.Igdb);
        _videoGameClient.TopRatedPages[1] = [Game("g1", 92, null)];

        await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // absent, not stored as zero - a missing score must read as "no rating", never as the worst one
        _upserted[0].Ratings.Should().NotContainKey(RatingSourceCatalog.IgdbCritic);
    }

    [Fact]
    public async Task RefreshAsync_WhenOneRankingFails_StillRefreshesTheOthers()
    {
        AllRankingsFresh();
        RankingIsStale(ExploreItemType.Movie, "tmdb");
        RankingIsStale(ExploreItemType.VideoGame, RatingSourceCatalog.Igdb);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ThrowsAsync(new HttpRequestException("TMDB is down"));
        _videoGameClient.TopRatedPages[1] = [Game("g1", 92, 96)];

        var result = await CreateService().RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // one provider being down must not cost the run the rankings it could have rebuilt
        result.RankingsRefreshed.Should().Be(1);
        _upserted.Should().ContainSingle().Which.ExternalId.Should().Be("g1");
    }

    [Fact]
    public async Task RefreshAsync_BackfillsImdbRatings_OnlyWhenImdbIsTheSelectedSource()
    {
        var service = CreateService();
        AllRankingsFresh();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _catalogueRepository
            .Setup(r => r.FindMissingRatingAsync(ExploreItemType.Movie, "tmdb", "imdb", It.IsAny<DateTime>(), It.IsAny<int>()))
            .ReturnsAsync([new ExploreCatalogueEntryModel { ItemType = ExploreItemType.Movie, Ranking = "tmdb", ExternalId = "42", Rank = 1, Title = "Movie 42" }]);
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("42", It.IsAny<CancellationToken>())).ReturnsAsync("tt42");
        _omdbClient.Setup(c => c.GetRatingAsync("tt42", OmdbCallPriority.Background, It.IsAny<CancellationToken>()))
            .ReturnsAsync(OmdbLookupResult.Rated(new OmdbRating(8.4, 100)));

        var result = await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.ImdbRatingsBackfilled.Should().Be(1);
        _catalogueRepository.Verify(r => r.RecordRatingAttemptAsync(ExploreItemType.Movie, "tmdb", "42", "imdb", 8.4), Times.Once);
        // TV shows kept the default source, so they cost nothing
        _catalogueRepository.Verify(
            r => r.FindMissingRatingAsync(ExploreItemType.TvShow, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RefreshAsync_RecordsAnImdbAttemptEvenWhenOmdbHasNoRating()
    {
        var service = CreateService();
        AllRankingsFresh();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _catalogueRepository
            .Setup(r => r.FindMissingRatingAsync(ExploreItemType.Movie, "tmdb", "imdb", It.IsAny<DateTime>(), It.IsAny<int>()))
            .ReturnsAsync([new ExploreCatalogueEntryModel { ItemType = ExploreItemType.Movie, Ranking = "tmdb", ExternalId = "42", Rank = 1, Title = "Movie 42" }]);
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("42", It.IsAny<CancellationToken>())).ReturnsAsync((string?)null);

        var result = await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // without stamping the fruitless attempt, the same handful of unrated titles would consume the whole
        // per-pass budget every week and coverage would never move down the ranking.
        result.ImdbRatingsBackfilled.Should().Be(0);
        _catalogueRepository.Verify(r => r.RecordRatingAttemptAsync(ExploreItemType.Movie, "tmdb", "42", "imdb", null), Times.Once);
    }

    [Fact]
    public async Task RefreshAsync_WhenExploreIsForcedToTmdb_MakesNoImdbCallsAtAll()
    {
        var service = CreateService();
        AllRankingsFresh();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _appSettingRepository.Setup(r => r.GetExploreUseTmdbAsync()).ReturnsAsync(true);

        var result = await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.ImdbRatingsBackfilled.Should().Be(0);
        _omdbClient.Verify(c => c.GetRatingAsync(It.IsAny<string>(), It.IsAny<OmdbCallPriority>(), It.IsAny<CancellationToken>()), Times.Never);
        _catalogueRepository.Verify(
            r => r.FindMissingRatingAsync(It.IsAny<ExploreItemType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RefreshAsync_SizesTheImdbBackfill_ToWhatIsLeftOfTheDailyOmdbBudget()
    {
        var service = CreateService();
        AllRankingsFresh();
        SelectImdbFor("Movie");
        // the reference sync runs first on the same tick and has already taken most of the day's allowance
        _omdbCallBudget.Remaining = 7;

        await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        // the pass asks for exactly what it can afford, instead of a hardcoded per-domain guess that had to
        // assume the worst about the other consumer
        _catalogueRepository.Verify(
            r => r.FindMissingRatingAsync(ExploreItemType.Movie, "tmdb", "imdb", It.IsAny<DateTime>(), 7), Times.Once);
    }

    [Fact]
    public async Task RefreshAsync_SkipsTheImdbBackfillEntirely_WhenTheDailyOmdbBudgetIsAlreadySpent()
    {
        var service = CreateService();
        AllRankingsFresh();
        SelectImdbFor("Movie");
        _omdbCallBudget.Exhausted = true;

        var result = await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.ImdbRatingsBackfilled.Should().Be(0);
        // not even the query runs: every entry it returned would cost a TMDB call whose answer is unusable
        _catalogueRepository.Verify(
            r => r.FindMissingRatingAsync(It.IsAny<ExploreItemType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task RefreshAsync_DoesNotStampAnAttempt_WhenTheBudgetRanOutMidPass()
    {
        var service = CreateService();
        AllRankingsFresh();
        SelectImdbFor("Movie");
        _catalogueRepository
            .Setup(r => r.FindMissingRatingAsync(ExploreItemType.Movie, "tmdb", "imdb", It.IsAny<DateTime>(), It.IsAny<int>()))
            .ReturnsAsync([
                new ExploreCatalogueEntryModel { ItemType = ExploreItemType.Movie, Ranking = "tmdb", ExternalId = "42", Rank = 1, Title = "Movie 42" },
                new ExploreCatalogueEntryModel { ItemType = ExploreItemType.Movie, Ranking = "tmdb", ExternalId = "43", Rank = 2, Title = "Movie 43" }
            ]);
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync("tt42");
        // the last call of the day was spent by another replica between sizing the pass and running it
        _omdbClient
            .Setup(c => c.GetRatingAsync(It.IsAny<string>(), OmdbCallPriority.Background, It.IsAny<CancellationToken>()))
            .Callback(() => _omdbCallBudget.Exhausted = true)
            .ReturnsAsync(OmdbLookupResult.NotAttempted);

        var result = await service.RefreshAsync(TimeSpan.FromDays(7), TestContext.Current.CancellationToken);

        result.ImdbRatingsBackfilled.Should().Be(0);
        // stamping here would suppress these titles for the whole 90-day re-attempt window over a limit that
        // had nothing to do with them - they must simply be picked up again next pass
        _catalogueRepository.Verify(
            r => r.RecordRatingAttemptAsync(
                It.IsAny<ExploreItemType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<double?>()), Times.Never);
        // and the pass stops rather than paying a TMDB call for every remaining entry
        _tmdbClient.Verify(c => c.GetMovieImdbIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    private void SelectImdbFor(string domain) =>
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { [domain] = "imdb" });
}
