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
    private readonly Mock<IAppSettingRepository> _appSettingRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IExploreDismissalRepository> _dismissalRepository = new();

    private ExploreService CreateService()
    {
        // no admin override by default => the code default source (tmdb) is used
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string>());
        return new(
            _tmdbClient.Object, _omdbClient.Object, _appSettingRepository.Object, _movieRepository.Object, _tvShowRepository.Object,
            _movieReferenceRepository.Object, _tvShowReferenceRepository.Object, _dismissalRepository.Object);
    }

    private static TmdbTopRatedItem Item(string id, double rating) => new(id, $"Title {id}", 2000, "synopsis", "http://img", rating);

    [Fact]
    public async Task GetSuggestionsAsync_ExcludesTitlesTheOwnerTracksOrHasDismissed_AndMapsTheRating()
    {
        // owner tracks reference "ref-a", whose TMDB id is "100"
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync(["ref-a"]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.Is<IReadOnlyCollection<string>>(c => c.Contains("ref-a"))))
            .ReturnsAsync([new MovieReferenceModel { Id = "ref-a", Title = "Tracked", TitleNormalized = "tracked", ExternalIds = new Dictionary<string, string> { ["tmdb"] = "100" } }]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie)).ReturnsAsync(["200"]);
        // later pages are empty (the real client returns [] past the last page); only page 1 has results here
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>()))
            .ReturnsAsync([Item("100", 9.0), Item("200", 8.8), Item("300", 8.6)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24);

        // 100 is tracked, 200 is dismissed - only 300 survives
        suggestions.Should().ContainSingle();
        suggestions[0].ExternalId.Should().Be("300");
        suggestions[0].Rating.Should().Be(8.6);
        suggestions[0].RatingScale.Should().Be(10);
    }

    [Fact]
    public async Task GetSuggestionsAsync_PagesThroughTheProviderUntilTheLimitIsFilled()
    {
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie)).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("1", 9.0), Item("2", 8.9)]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(2, It.IsAny<CancellationToken>())).ReturnsAsync([Item("3", 8.8), Item("4", 8.7)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 3);

        suggestions.Select(s => s.ExternalId).Should().Equal(["1", "2", "3"], "it stops once the limit is filled, having pulled a second page");
        _tmdbClient.Verify(c => c.GetTopRatedMoviesAsync(3, It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_UsesTheTvShowProviderAndRepositories_ForTheTvShowDomain()
    {
        _tvShowRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.TvShow)).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedTvShowsAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedTvShowsAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("tv1", 9.4)]);

        var suggestions = await CreateService().GetSuggestionsAsync(ExploreItemType.TvShow, "owner", 24);

        suggestions.Should().ContainSingle().Which.ExternalId.Should().Be("tv1");
        _tmdbClient.Verify(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenImdbIsThePrimarySource_ShowsImdbRatingsButKeepsTmdbOrder()
    {
        var service = CreateService();
        // admin picked IMDb as the movie primary source
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie)).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        // TMDB top-rated order: "20" before "10"
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("20", 9.0), Item("10", 5.0)]);
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("20", It.IsAny<CancellationToken>())).ReturnsAsync("tt20");
        _tmdbClient.Setup(c => c.GetMovieImdbIdAsync("10", It.IsAny<CancellationToken>())).ReturnsAsync("tt10");
        _omdbClient.Setup(c => c.GetRatingAsync("tt20", It.IsAny<CancellationToken>())).ReturnsAsync(new OmdbRating(7.0, 50));
        _omdbClient.Setup(c => c.GetRatingAsync("tt10", It.IsAny<CancellationToken>())).ReturnsAsync(new OmdbRating(8.5, 100));

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24);

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
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie)).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(It.IsAny<int>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _tmdbClient.Setup(c => c.GetTopRatedMoviesAsync(1, It.IsAny<CancellationToken>())).ReturnsAsync([Item("20", 9.0), Item("10", 5.0)]);

        var suggestions = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24);

        // TMDB order and TMDB ratings, despite IMDb being the primary source
        suggestions.Select(s => s.ExternalId).Should().Equal(["20", "10"]);
        suggestions[0].Rating.Should().Be(9.0);
        _tmdbClient.Verify(c => c.GetMovieImdbIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        _omdbClient.Verify(c => c.GetRatingAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DismissAsync_RecordsADismissalKeyedByExternalId()
    {
        await CreateService().DismissAsync(ExploreItemType.TvShow, "owner", "tv9");

        _dismissalRepository.Verify(r => r.AddAsync(It.Is<ExploreDismissalModel>(m =>
            m.OwnerId == "owner" && m.ReferenceType == ExploreItemType.TvShow && m.ExternalId == "tv9")), Times.Once);
    }

    [Fact]
    public async Task UndismissAsync_RemovesTheDismissal()
    {
        await CreateService().UndismissAsync(ExploreItemType.Movie, "owner", "42");

        _dismissalRepository.Verify(r => r.RemoveAsync("owner", ExploreItemType.Movie, "42"), Times.Once);
    }
}
