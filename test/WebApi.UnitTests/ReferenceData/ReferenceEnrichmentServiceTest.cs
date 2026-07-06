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
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();

    private ReferenceEnrichmentService CreateService(FakeTmdbClient tmdbClient) => new(
        tmdbClient, _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _tvShowRepository.Object, _movieRepository.Object);

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchReturnsNoResults()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceIdForTitleYearAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(
            new TmdbSearchResult("1", "Some Show", 2020, null),
            new TmdbSearchResult("2", "Some Show", 2020, null)));

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceIdForTitleYearAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults(new TmdbSearchResult("42", "Some Show", 2020, "Synopsis"));
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", []);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        var service = CreateService(tmdbClient);

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.ExternalIds["tmdb"] == "42")), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceIdForTitleYearAsync("Some Show", 2020, It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PropagatesTheUpsertedReferenceId()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", []);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id = "reference-1"; return m; });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        result.Id.Should().Be("reference-1");
        _tvShowRepository.Verify(r => r.SetReferenceIdForTitleYearAsync("Some Show", 2020, "reference-1"), Times.Once);
    }

    private sealed class FakeTmdbClient : ITmdbClient
    {
        private readonly List<TmdbSearchResult> _tvShowSearchResults;

        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

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
    }
}
