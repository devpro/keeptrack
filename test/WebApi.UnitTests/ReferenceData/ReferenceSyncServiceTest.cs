using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

// the Domain status enum, not the Contracts one the WebApi.Contracts.Dto using also imports
using TvShowStatus = Keeptrack.Domain.Models.TvShowStatus;

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
    private readonly Mock<IEpisodeRepository> _episodeRepository = new();

    private ReferenceSyncService CreateService(FakeTmdbClient tmdbClient)
    {
        _bookReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _videoGameReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _albumReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);

        var bookRatingLookup = new Mock<IBookRatingByIsbnLookup>();
        bookRatingLookup.Setup(x => x.GetRatingByIsbnAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(((double?)null, (int?)null));
        var appSettingRepository = new Mock<IAppSettingRepository>();
        appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string>());
        var videoGameClients = new ReferenceClientRegistry<IVideoGameReferenceClient>([FakeVideoGameReferenceClient.Empty()], RatingSourceCatalog.Igdb);
        var enrichmentService = new ReferenceEnrichmentService(
            tmdbClient, FakeOmdbClient.Empty(), new FakeOmdbCallBudget(), new ReferenceClientRegistry<IBookReferenceClient>([FakeBookReferenceClient.Empty()], "openlibrary"), bookRatingLookup.Object, videoGameClients, FakeDiscogsClient.Empty(),
            _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
            _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
            _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object,
            appSettingRepository.Object, new RatingSourceOptions(videoGameClients), NullLogger<ReferenceEnrichmentService>.Instance);
        var reconciliationService = new TvShowStatusReconciliationService(
            _tvShowRepository.Object, _episodeRepository.Object, _tvShowReferenceRepository.Object, NullLogger<TvShowStatusReconciliationService>.Instance);
        return new ReferenceSyncService(
            _tvShowReferenceRepository.Object, _movieReferenceRepository.Object,
            _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
            enrichmentService, reconciliationService, NullLogger<ReferenceSyncService>.Instance);
    }

    /// <summary>
    /// The staleness cutoff is a query, not an in-memory check over the collection, so this asserts each domain is asked for the right window and a bounded page of it.
    /// Which documents that window returns, and in what order, is MongoDB semantics, pinned by <c>ReferenceStalenessRepositoryTest</c> against a real database.
    /// </summary>
    [Fact]
    public async Task SyncStaleReferencesAsync_AsksEachDomainForItsStalestDocuments_BoundedPerPass()
    {
        var startedAt = DateTime.UtcNow;
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        var service = CreateService(FakeTmdbClient.Empty());

        await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), cancellationToken: TestContext.Current.CancellationToken);

        _tvShowReferenceRepository.Verify(
            r => r.FindStaleAsync(It.Is<DateTime>(cutoff => cutoff >= startedAt.AddDays(-3) && cutoff <= startedAt.AddDays(-3).AddMinutes(1)),
                It.Is<int>(limit => limit > 0)), Times.Once);
        _movieReferenceRepository.Verify(
            r => r.FindStaleAsync(It.IsAny<DateTime>(), It.Is<int>(limit => limit > 0)), Times.Once);
        _bookReferenceRepository.Verify(
            r => r.FindStaleAsync(It.IsAny<DateTime>(), It.Is<int>(limit => limit > 0)), Times.Once);
        _videoGameReferenceRepository.Verify(
            r => r.FindStaleAsync(It.IsAny<DateTime>(), It.Is<int>(limit => limit > 0)), Times.Once);
        _albumReferenceRepository.Verify(
            r => r.FindStaleAsync(It.IsAny<DateTime>(), It.Is<int>(limit => limit > 0)), Times.Once);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_Refreshes_ReferenceOlderThanStaleAfter()
    {
        var tmdbClient = FakeTmdbClient.Empty();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-1", Title = "Some Show", TitleNormalized = "some show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, LastEnrichedAt = DateTime.UtcNow.AddDays(-10)
            }
        ]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), cancellationToken: TestContext.Current.CancellationToken);

        result.TvShowsChecked.Should().Be(1);
        result.TvShowsUpdated.Should().Be(1);
    }

    /// <summary>
    /// A rated reference enriched today, which TMDB reports unchanged since: the periodic pass trusts the change check, a forced one fetches anyway.
    /// The change check only sees changes after <c>LastEnrichedAt</c>, so one it missed is recovered only by forcing.
    /// </summary>
    private FakeTmdbClient SetupRecentlyEnrichedTvShowAndMovieReportedUnchanged()
    {
        var tmdbClient = FakeTmdbClient.Empty();
        tmdbClient.ChangedSince["42"] = false;
        tmdbClient.ChangedSince["603"] = false;
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2023, "Synopsis", [new TmdbEpisode(4, 1, "S4E1", new DateOnly(2026, 10, 15))], [], null);
        tmdbClient.MovieDetails["603"] = new TmdbMovieDetails("603", "Some Movie", 1999, "Synopsis", [], null, 8.2, 100);
        var ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 8.0, Scale = 10, Count = 100 } };
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-1", Title = "Some Show", TitleNormalized = "some show",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, Ratings = new(ratings), LastEnrichedAt = DateTime.UtcNow
            }
        ]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([
            new MovieReferenceModel
            {
                Id = "reference-2", Title = "Some Movie", TitleNormalized = "some movie",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "603" }, Ratings = new(ratings), LastEnrichedAt = DateTime.UtcNow
            }
        ]);
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        return tmdbClient;
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_FetchesTvShowsAndMoviesInFull_WhenForced_EvenIfTmdbReportsNoChange()
    {
        var tmdbClient = SetupRecentlyEnrichedTvShowAndMovieReportedUnchanged();
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(ReferenceSyncWindows.Forced.References, fullFetch: ReferenceSyncWindows.Forced.FullFetch,
            cancellationToken: TestContext.Current.CancellationToken);

        result.TvShowsUpdated.Should().Be(1);
        result.MoviesUpdated.Should().Be(1);
        tmdbClient.ChangesRequested.Should().BeEmpty();
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.Episodes.Exists(e => e.SeasonNumber == 4))), Times.Once);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_TrustsTmdbsChangeCheck_OnThePeriodicPass()
    {
        var tmdbClient = SetupRecentlyEnrichedTvShowAndMovieReportedUnchanged();
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(ReferenceSyncWindows.Periodic.References, fullFetch: ReferenceSyncWindows.Periodic.FullFetch,
            cancellationToken: TestContext.Current.CancellationToken);

        result.TvShowsUpdated.Should().Be(0);
        result.MoviesUpdated.Should().Be(0);
        tmdbClient.ChangesRequested.Should().BeEquivalentTo(["42", "603"]);
    }

    /// <summary>
    /// A forced pass spends far longer on movies, books, video games and albums than on TV,
    /// and finished shows only depend on the TV guides, so they are reopened before the next domain starts.
    /// </summary>
    [Fact]
    public async Task SyncStaleReferencesAsync_ReopensFinishedShows_RightAfterTheTvShowsAndBeforeTheMovies()
    {
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindFinishedLinkedShowsAsync()).ReturnsAsync([
            new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "The Diplomat", State = TvShowStatus.Finished, ReferenceId = "reference-1" }
        ]);
        _episodeRepository.Setup(r => r.FindByShowIdsAsync("owner", It.IsAny<IReadOnlyCollection<string>>()))
            .ReturnsAsync([new EpisodeModel { OwnerId = "owner", TvShowId = "show-1", SeasonNumber = 3, EpisodeNumber = 8 }]);
        _tvShowReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>())).ReturnsAsync([
            new TvShowReferenceModel
            {
                Id = "reference-1", Title = "The Diplomat", TitleNormalized = "the diplomat", ExternalIds = new Dictionary<string, string>(),
                Episodes = [new ReferenceEpisodeModel { SeasonNumber = 4, EpisodeNumber = 1, Title = "S4E1", AirDate = new DateOnly(2026, 10, 15) }]
            }
        ]);
        var reopenedBeforeMovies = false;
        var service = CreateService(FakeTmdbClient.Empty());

        var result = await service.SyncStaleReferencesAsync(TimeSpan.Zero, stage =>
            {
                if (stage == ReferenceSyncStage.SyncingMovies)
                {
                    reopenedBeforeMovies = _tvShowRepository.Invocations.Any(i => i.Method.Name == nameof(ITvShowRepository.UpdateAsync));
                }
                return Task.CompletedTask;
            },
            cancellationToken: TestContext.Current.CancellationToken);

        reopenedBeforeMovies.Should().BeTrue();
        result.FinishedShowsReopened.Should().Be(1);
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(s => s.State == TvShowStatus.Current), "owner", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_StillSyncsTheOtherDomains_WhenTheReconciliationFails()
    {
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindFinishedLinkedShowsAsync()).ThrowsAsync(new InvalidOperationException("Simulated MongoDB failure."));
        var service = CreateService(FakeTmdbClient.Empty());

        await service.SyncStaleReferencesAsync(TimeSpan.Zero, cancellationToken: TestContext.Current.CancellationToken);

        _albumReferenceRepository.Verify(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public async Task SyncStaleReferencesAsync_ContinuesPastAFailedReference_AndStillProcessesTheRest()
    {
        var tmdbClient = FakeTmdbClient.Empty();
        tmdbClient.TvShowDetails["good"] = new TmdbTvShowDetails("good", "Good Show", 2020, null, [], [], null);
        tmdbClient.ThrowForTmdbId = "bad";
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([
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
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.SyncStaleReferencesAsync(TimeSpan.FromDays(3), cancellationToken: TestContext.Current.CancellationToken);

        result.TvShowsChecked.Should().Be(2);
        result.TvShowsUpdated.Should().Be(1);
    }

    /// <summary>
    /// Backs the admin "sync now" progress bar (<c>ReferenceDataAdminController.SyncNow</c>, <c>ReferenceDataAdminPage.razor</c>'s polling loop),
    /// the stage callback firing once per domain in the order the UI's progress mapping assumes.
    /// </summary>
    [Fact]
    public async Task SyncStaleReferencesAsync_InvokesOnStageChanged_OncePerDomainInOrder()
    {
        _tvShowReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindStaleAsync(It.IsAny<DateTime>(), It.IsAny<int>())).ReturnsAsync([]);
        var service = CreateService(FakeTmdbClient.Empty());
        var stages = new List<ReferenceSyncStage>();

        await service.SyncStaleReferencesAsync(
            TimeSpan.FromDays(3),
            stage =>
            {
                stages.Add(stage);
                return Task.CompletedTask;
            },
            cancellationToken: TestContext.Current.CancellationToken);

        stages.Should().ContainInOrder(
            ReferenceSyncStage.SyncingTvShows,
            ReferenceSyncStage.SyncingMovies,
            ReferenceSyncStage.SyncingBooks,
            ReferenceSyncStage.SyncingVideoGames,
            ReferenceSyncStage.SyncingAlbums);
    }

    private sealed class FakeTmdbClient : ITmdbClient
    {
        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

        public Dictionary<string, TmdbMovieDetails> MovieDetails { get; } = new();

        public string? ThrowForTmdbId { get; set; }

        /// <summary>The answer of TMDB's change check, keyed by tmdb id, a change by default.</summary>
        public Dictionary<string, bool> ChangedSince { get; } = new();

        public List<string> ChangesRequested { get; } = [];

        public static FakeTmdbClient Empty() => new();

        public Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedMoviesAsync(int page, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbTopRatedItem>>([]);

        public Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedTvShowsAsync(int page, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbTopRatedItem>>([]);

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

        public Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default)
        {
            ChangesRequested.Add(tmdbId);
            return Task.FromResult(ChangedSince.GetValueOrDefault(tmdbId, true));
        }

        public Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default)
        {
            ChangesRequested.Add(tmdbId);
            return Task.FromResult(ChangedSince.GetValueOrDefault(tmdbId, true));
        }

        public Task<string?> GetTvShowImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(null);

        public Task<string?> GetMovieImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(null);
    }
}
