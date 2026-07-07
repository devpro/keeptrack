using System.Collections.Generic;
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
public class ReferenceEnrichmentServiceTest
{
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<IPersonReferenceRepository> _personReferenceRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();

    private ReferenceEnrichmentService CreateService(FakeTmdbClient tmdbClient) => new(
        tmdbClient, _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
        _tvShowRepository.Object, _movieRepository.Object);

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchReturnsNoResults()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(
            new TmdbSearchResult("1", "Some Show", 2020, null, null),
            new TmdbSearchResult("2", "Some Show", 2020, null, null)));

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults(new TmdbSearchResult("42", "Some Show", 2020, "Synopsis", null));
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        var service = CreateService(tmdbClient);

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.ExternalIds["tmdb"] == "42")), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, It.IsAny<string>(), "Some Show"), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PropagatesTheUpsertedReferenceId()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id = "reference-1"; return m; });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        result.Id.Should().Be("reference-1");
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, "reference-1", "Some Show"), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_ReusesTheSameReferenceByTmdbId_EvenWhenTitleTextDiffersEntirely()
    {
        // regression test: resolving the exact same TMDB show twice under two completely unrelated title
        // strings (e.g. a translation an admin didn't recognize) used to create a second, duplicate
        // reference document, because the "does this already exist" check only ever looked at title/year -
        // tmdbId is now checked first and is authoritative.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByExternalIdAsync("tmdb", "42"))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1", Title = "The Wire", TitleNormalized = "the wire", ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, MatchedTitles = ["the wire"]
            });
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Totally Unrelated Search Text", null, "42");

        result.Id.Should().Be("reference-1");
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.Id == "reference-1")), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_RecordsBothTheSearchedAndCanonicalTitleAsMatchedTitles()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "reference-1"; return m; });
        var service = CreateService(tmdbClient);

        // the tenant searched with a different-language title than TMDB's canonical English one
        await service.ResolveTvShowAsync("Le Fil", 2002, "42");

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(
            m => m.MatchedTitles.Contains("the wire") && m.MatchedTitles.Contains("le fil"))), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PreservesPreviouslyKnownMatchedTitles_WhenReResolvingAnExistingReference()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Le Fil", 2002))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1", Title = "The Wire", TitleNormalized = "the wire", ExternalIds = [], MatchedTitles = ["the wire", "il filo"]
            });
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        await service.ResolveTvShowAsync("Le Fil", 2002, "42");

        // an alias contributed by a third tenant earlier (il filo) must survive a later re-resolution
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(
            m => m.MatchedTitles.Contains("the wire") && m.MatchedTitles.Contains("il filo") && m.MatchedTitles.Contains("le fil"))), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_ReusesExistingPersonReference_ForAnAlreadyKnownActor()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        tmdbClient.Cast["42"] = [new TmdbCastMember("99", "Actor Name", "A Character", 0, null)];

        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "reference-1"; return m; });
        _personReferenceRepository
            .Setup(r => r.FindByExternalIdAsync("tmdb", "99"))
            .ReturnsAsync(new PersonReferenceModel { Id = "person-1", Name = "Actor Name", ExternalIds = new Dictionary<string, string> { ["tmdb"] = "99" } });
        _personReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>()))
            .ReturnsAsync((PersonReferenceModel m) => m);

        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        // the same actor already known from a previous resolution must be reused, not duplicated
        _personReferenceRepository.Verify(r => r.UpsertAsync(It.Is<PersonReferenceModel>(m => m.Id == "person-1")), Times.Once);
        result.Cast.Should().ContainSingle(c => c.PersonReferenceId == "person-1" && c.CharacterName == "A Character");
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_RelinksToTheNewMatch_WhenTitleWasEditedAwayFromTheCurrentLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "A Different Show", Year = 2021, ReferenceId = "old-reference" };
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("A Different Show", 2021))
            .ReturnsAsync(new TvShowReferenceModel { Id = "new-reference", Title = "A Different Show", TitleNormalized = "a different show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("new-reference");
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == "new-reference"), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 2020, ReferenceId = "old-reference" };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 2020)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository.Setup(r => r.FindByTitleAsync("Some Show")).ReturnsAsync((TvShowReferenceModel?)null);

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        // no match for the current title means the previously stored link no longer corresponds to what
        // the tenant just told us is correct - clear it (which also puts it back in the admin's unresolved queue)
        result.ReferenceId.Should().BeEmpty();
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_FallsBackToTitleOnlyMatch_WhenTheTenantHasNoYearSet()
    {
        // regression test: the title-only fallback used to be skipped whenever Year was null, which meant
        // any linked show with no recorded year would unlink itself on every refresh, since the title+year
        // query can never succeed with a null year against a reference that has a real one.
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = null, ReferenceId = "reference-1" };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", null)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Some Show"))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", Year = 2020, ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_LinksAndUpdatesTitle_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Typo'd Show", Year = 2020 };
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Show", 2020))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Show");
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Show", 2020, "reference-1", "Some Show"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_FallsBackToTitleOnlyMatch_WhenTitleYearMatchMisses()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 1999 };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 1999)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Some Show"))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_ReturnsUnchanged_WhenNoMatchFound()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 2020 };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 2020)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository.Setup(r => r.FindByTitleAsync("Some Show")).ReturnsAsync((TvShowReferenceModel?)null);

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        // was never linked and still isn't - nothing to clear, so no write should happen at all
        result.ReferenceId.Should().BeNullOrEmpty();
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_LinksAndUpdatesTitle_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Typo'd Movie", Year = 2020 };
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Movie", 2020))
            .ReturnsAsync(new MovieReferenceModel { Id = "reference-1", Title = "Some Movie", TitleNormalized = "some movie", ExternalIds = [] });

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Movie");
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Movie", 2020, "reference-1", "Some Movie"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Movie", Year = 2020, ReferenceId = "old-reference" };
        _movieReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Movie", 2020)).ReturnsAsync((MovieReferenceModel?)null);
        _movieReferenceRepository.Setup(r => r.FindByTitleAsync("Some Movie")).ReturnsAsync((MovieReferenceModel?)null);

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    private sealed class FakeTmdbClient : ITmdbClient
    {
        private readonly List<TmdbSearchResult> _tvShowSearchResults;

        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

        public Dictionary<string, List<TmdbCastMember>> Cast { get; } = new();

        private FakeTmdbClient(List<TmdbSearchResult> tvShowSearchResults) => _tvShowSearchResults = tvShowSearchResults;

        public static FakeTmdbClient WithTvShowSearchResults(params TmdbSearchResult[] results) => new([.. results]);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>(_tvShowSearchResults);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>([]);

        public Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult(TvShowDetails.GetValueOrDefault(tmdbId));

        public Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<TmdbMovieDetails?>(null);

        public Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>(Cast.GetValueOrDefault(tmdbId) ?? []);

        public Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>([]);
    }
}
