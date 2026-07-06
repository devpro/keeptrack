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
