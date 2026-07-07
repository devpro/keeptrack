using System;
using System.Collections.Generic;
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

[Trait("Category", "UnitTests")]
public class ReferenceSyncServiceTest
{
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<IPersonReferenceRepository> _personReferenceRepository = new();
    private readonly Mock<IBookReferenceRepository> _bookReferenceRepository = new();
    private readonly Mock<IVideoGameReferenceRepository> _videoGameReferenceRepository = new();
    private readonly Mock<IAlbumReferenceRepository> _albumReferenceRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();
    private readonly Mock<IBookRepository> _bookRepository = new();
    private readonly Mock<IVideoGameRepository> _videoGameRepository = new();
    private readonly Mock<IAlbumRepository> _albumRepository = new();

    private ReferenceSyncService CreateService(FakeTmdbClient tmdbClient)
    {
        _bookReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _videoGameReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _albumReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);

        var enrichmentService = new ReferenceEnrichmentService(
            tmdbClient, FakeOpenLibraryClient.Empty(), FakeRawgClient.Empty(), FakeDiscogsClient.Empty(),
            _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
            _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
            _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object);
        return new ReferenceSyncService(
            _tvShowReferenceRepository.Object, _movieReferenceRepository.Object,
            _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
            enrichmentService, NullLogger<ReferenceSyncService>.Instance);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_Skips_ReferenceEnrichedMoreRecentlyThanStaleAfter()
    {
        _tvShowReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-1", Title = "Some Show", TitleNormalized = "some show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, LastEnrichedAt = DateTime.UtcNow
            }
        ]);
        _movieReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        var service = CreateService(FakeTmdbClient.Empty());

        var result = await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), TestContext.Current.CancellationToken);

        result.TvShowsChecked.Should().Be(0);
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()), Times.Never);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_Refreshes_ReferenceOlderThanStaleAfter()
    {
        var tmdbClient = FakeTmdbClient.Empty();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-1", Title = "Some Show", TitleNormalized = "some show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, LastEnrichedAt = DateTime.UtcNow.AddDays(-10)
            }
        ]);
        _movieReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), TestContext.Current.CancellationToken);

        result.TvShowsChecked.Should().Be(1);
        result.TvShowsUpdated.Should().Be(1);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_ContinuesPastAFailedReference_AndStillProcessesTheRest()
    {
        var tmdbClient = FakeTmdbClient.Empty();
        tmdbClient.TvShowDetails["good"] = new TmdbTvShowDetails("good", "Good Show", 2020, null, [], [], null);
        tmdbClient.ThrowForTmdbId = "bad";
        _tvShowReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-bad", Title = "Bad Show", TitleNormalized = "bad show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "bad" }, LastEnrichedAt = null
            },
            new TvShowReferenceModel
            {
                Id = "reference-good", Title = "Good Show", TitleNormalized = "good show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "good" }, LastEnrichedAt = null
            }
        ]);
        _movieReferenceRepository.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), TestContext.Current.CancellationToken);

        result.TvShowsChecked.Should().Be(2);
        result.TvShowsUpdated.Should().Be(1);
    }

    private sealed class FakeTmdbClient : ITmdbClient
    {
        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

        public Dictionary<string, TmdbMovieDetails> MovieDetails { get; } = new();

        public string? ThrowForTmdbId { get; set; }

        public static FakeTmdbClient Empty() => new();

        public Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>([]);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>([]);

        public Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            if (tmdbId == ThrowForTmdbId) throw new InvalidOperationException("Simulated TMDB failure.");
            return Task.FromResult(TvShowDetails.GetValueOrDefault(tmdbId));
        }

        public Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            if (tmdbId == ThrowForTmdbId) throw new InvalidOperationException("Simulated TMDB failure.");
            return Task.FromResult(MovieDetails.GetValueOrDefault(tmdbId));
        }

        public Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>([]);

        public Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>([]);

        public Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
