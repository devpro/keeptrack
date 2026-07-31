using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class ExploreServiceTest
{
    private readonly Mock<ITmdbClient> _tmdbClient = new();
    private readonly Mock<IOmdbClient> _omdbClient = new();
    private readonly Mock<IRawgClient> _rawgClient = new();
    private readonly Mock<IAppSettingRepository> _appSettingRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IVideoGameRepository> _videoGameRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IVideoGameReferenceRepository> _videoGameReferenceRepository = new();
    private readonly Mock<IExploreDismissalRepository> _dismissalRepository = new();

    private ExploreService CreateService()
    {
        // no admin override by default => the code default source per domain (tmdb / rawg) is used
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string>());
        return new(
            _tmdbClient.Object, _omdbClient.Object, _rawgClient.Object, _appSettingRepository.Object,
            _movieRepository.Object, _tvShowRepository.Object, _videoGameRepository.Object,
            _movieReferenceRepository.Object, _tvShowReferenceRepository.Object, _videoGameReferenceRepository.Object,
            _dismissalRepository.Object);
    }

    private static TmdbTopRatedItem Item(string id, double rating) => new(id, $"Title {id}", 2000, "synopsis", "http://img", rating);

    private static RawgTopRatedItem Game(string id, double? rating, int? metacritic) => new(id, $"Game {id}", 2010, "http://img", rating, metacritic);

    // "this owner tracks nothing and has dismissed nothing" - the starting point of every test that isn't
    // specifically about the exclusion set.
    private void NoExclusions(ExploreItemType type)
    {
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", type, It.IsAny<string>())).ReturnsAsync([]);
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _videoGameRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _movieRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _videoGameRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _videoGameReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ExcludesTitlesTheOwnerTracksOrHasDismissed_AndMapsTheRating()
    {
        NoExclusions(ExploreItemType.Movie);
        // owner tracks reference "ref-a", whose TMDB id is "100"
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync(["ref-a"]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.Is<IReadOnlyCollection<string>>(c => c.Contains("ref-a"))))
            .ReturnsAsync([new MovieReferenceModel { Id = "ref-a", Title = "Tracked", TitleNormalized = "tracked", ExternalIds = new Dictionary<string, string> { ["tmdb"] = "100" } }]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie, "tmdb")).ReturnsAsync(["200"]);
        // later pages are empty (the real client returns [] past the last page); only page 1 has results here
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>()))
            .ReturnsAsync([Item("100", 9.0), Item("200", 8.8), Item("300", 8.6)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, TestContext.Current.CancellationToken);

        // 100 is tracked, 200 is dismissed - only 300 survives
        suggestions.Should().ContainSingle();
        suggestions[0].ExternalId.Should().Be("300");
        suggestions[0].Rating.Should().Be(8.6);
        suggestions[0].RatingScale.Should().Be(10);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ExcludesATitleTheOwnerTracks_EvenWhenItHasNoReferenceLink()
    {
        NoExclusions(ExploreItemType.Movie);
        // an item the owner typed in or imported that never got linked has no provider id to exclude by -
        // only its title. Matching goes through the app-wide TitleNormalizer, so it is exactly as forgiving
        // as every other title match in the codebase (case and surrounding whitespace), no more.
        _movieRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([" the GODFATHER "]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>()))
            .ReturnsAsync([new TmdbTopRatedItem("1", "The Godfather", 1972, null, null, 8.7), Item("2", 8.6)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, TestContext.Current.CancellationToken);

        suggestions.Should().ContainSingle().Which.ExternalId.Should().Be("2");
    }

    [Fact]
    public async Task GetSuggestionsAsync_PagesThroughTheProviderUntilTheLimitIsFilled()
    {
        NoExclusions(ExploreItemType.Movie);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("1", 9.0), Item("2", 8.9)]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(2, It.IsAny<CancellationToken>())).ReturnsAsync([Item("3", 8.8), Item("4", 8.7)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 3, TestContext.Current.CancellationToken);

        suggestions.Select(s => s.ExternalId).Should().Equal(["1", "2", "3"], "it stops once the limit is filled, having pulled a second page");
        _tmdbClient.Verify(c => c.GetTopRatedMoviesAsync(3, It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_UsesTheTvShowProviderAndRepositories_ForTheTvShowDomain()
    {
        NoExclusions(ExploreItemType.TvShow);
        _tmdbClient.Setup(c => c.GetTopRatedTvShowsAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedTvShowsAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("tv1", 9.4)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.TvShow, "owner", 24, TestContext.Current.CancellationToken);

        suggestions.Should().ContainSingle().Which.ExternalId.Should().Be("tv1");
        _tmdbClient.Verify(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenImdbIsThePrimarySource_ShowsImdbRatingsButKeepsTmdbOrder()
    {
        var service = CreateService();
        // admin picked IMDb as the movie primary source
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        NoExclusions(ExploreItemType.Movie);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        // TMDB top-rated order: "20" before "10"
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("20", 9.0), Item("10", 5.0)]);
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("20", It.IsAny<CancellationToken>())).ReturnsAsync("tt20");
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("10", It.IsAny<CancellationToken>())).ReturnsAsync("tt10");
        _omdbClient.Setup(c => c.GetRatingAsync("tt20", It.IsAny<CancellationToken>())).ReturnsAsync(new OmdbRating(7.0, 50));
        _omdbClient.Setup(c => c.GetRatingAsync("tt10", It.IsAny<CancellationToken>())).ReturnsAsync(new OmdbRating(8.5, 100));

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, TestContext.Current.CancellationToken);

        // the shown value is IMDb's, but the ORDER stays TMDB's (no re-rank from partial OMDb data)
        suggestions.Select(s => s.ExternalId).Should().Equal(["20", "10"]);
        suggestions[0].Rating.Should().Be(7.0);
        suggestions[1].Rating.Should().Be(8.5);
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenExploreIsForcedToTmdb_IgnoresTheImdbPrimarySource_AndMakesNoOmdbCalls()
    {
        var service = CreateService();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _appSettingRepository.Setup(r => r.GetExploreUseTmdbAsync()).ReturnsAsync(true);
        NoExclusions(ExploreItemType.Movie);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("20", 9.0), Item("10", 5.0)]);

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, TestContext.Current.CancellationToken);

        // TMDB order and TMDB ratings, despite IMDb being the primary source
        suggestions.Select(s => s.ExternalId).Should().Equal(["20", "10"]);
        suggestions[0].Rating.Should().Be(9.0);
        _tmdbClient.Verify(c => c.GetMovieImdbIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        _omdbClient.Verify(c => c.GetRatingAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_ReadsRawgOrderedByItsOwnScore_ByDefault()
    {
        NoExclusions(ExploreItemType.VideoGame);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(1, "rawg", It.IsAny<CancellationToken>()))
            .ReturnsAsync([Game("g1", 4.7, 96), Game("g2", 4.5, 92)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, TestContext.Current.CancellationToken);

        suggestions.Select(s => s.ExternalId).Should().Equal(["g1", "g2"]);
        // RAWG's own score on its own 0-5 scale, taken straight off the listing - no per-title call
        suggestions[0].Rating.Should().Be(4.7);
        suggestions[0].RatingScale.Should().Be(5);
        _rawgClient.Verify(c => c.GetGameDetailsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_WhenMetacriticIsThePrimarySource_OrdersAndShowsMetacriticScores()
    {
        var service = CreateService();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = "metacritic" });
        NoExclusions(ExploreItemType.VideoGame);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(1, "metacritic", It.IsAny<CancellationToken>()))
            .ReturnsAsync([Game("g9", 4.1, 98)]);

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, TestContext.Current.CancellationToken);

        // RAWG orders by the selected source itself, so unlike IMDb there is nothing to enrich or re-rank
        suggestions.Should().ContainSingle().Which.ExternalId.Should().Be("g9");
        suggestions[0].Rating.Should().Be(98);
        suggestions[0].RatingScale.Should().Be(100);
        _rawgClient.Verify(c => c.GetTopRatedGamesAsync(It.IsAny<int>(), "rawg", It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_IsUnaffectedByTheForceTmdbExploreFlag()
    {
        var service = CreateService();
        // the flag exists only to keep movie/TV discovery off the per-title OMDb lookups - "tmdb" is not a
        // video game rating source at all, so it must never leak into this domain's ranking.
        _appSettingRepository.Setup(r => r.GetExploreUseTmdbAsync()).ReturnsAsync(true);
        NoExclusions(ExploreItemType.VideoGame);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(1, "rawg", It.IsAny<CancellationToken>())).ReturnsAsync([Game("g1", 4.7, 96)]);

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, TestContext.Current.CancellationToken);

        suggestions.Should().ContainSingle().Which.RatingScale.Should().Be(5);
        _tmdbClient.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_ExcludesGamesTheOwnerAlreadyTracks()
    {
        NoExclusions(ExploreItemType.VideoGame);
        _videoGameRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync(["ref-g"]);
        // the tracked game's reference carries the RAWG id - matched against the RAWG suggestion ids, never a TMDB one
        _videoGameReferenceRepository.Setup(r => r.FindByIdsAsync(It.Is<IReadOnlyCollection<string>>(c => c.Contains("ref-g"))))
            .ReturnsAsync([new VideoGameReferenceModel { Id = "ref-g", Title = "Owned", TitleNormalized = "owned", ExternalIds = new Dictionary<string, string> { ["rawg"] = "g1" } }]);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _rawgClient.Setup(c => c.GetTopRatedGamesAsync(1, "rawg", It.IsAny<CancellationToken>()))
            .ReturnsAsync([Game("g1", 4.7, 96), Game("g2", 4.5, 92)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, TestContext.Current.CancellationToken);

        suggestions.Should().ContainSingle().Which.ExternalId.Should().Be("g2");
    }

    [Fact]
    public async Task DismissAsync_RecordsADismissalKeyedByTheDomainsDiscoveryProvider()
    {
        var service = CreateService();

        await service.DismissAsync(ExploreItemType.TvShow, "owner", "tv9");
        await service.DismissAsync(ExploreItemType.VideoGame, "owner", "g9");

        _dismissalRepository.Verify(r => r.AddAsync(It.Is<ExploreDismissalModel>(m =>
            m.OwnerId == "owner" && m.ItemType == ExploreItemType.TvShow && m.ExternalSource == "tmdb" && m.ExternalId == "tv9")), Times.Once);
        // a RAWG id and a TMDB id are both plain integers, so the provider is stored, never inferred
        _dismissalRepository.Verify(r => r.AddAsync(It.Is<ExploreDismissalModel>(m =>
            m.OwnerId == "owner" && m.ItemType == ExploreItemType.VideoGame && m.ExternalSource == "rawg" && m.ExternalId == "g9")), Times.Once);
    }

    [Fact]
    public async Task UndismissAsync_RemovesTheDismissal()
    {
        await CreateService().UndismissAsync(ExploreItemType.Movie, "owner", "42");

        _dismissalRepository.Verify(r => r.RemoveAsync("owner", ExploreItemType.Movie, "tmdb", "42"), Times.Once);
    }
}
