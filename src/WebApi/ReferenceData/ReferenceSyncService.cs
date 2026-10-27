using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps the shared reference collections up to date with their providers, since provider data (air dates, genres, covers, cast, ratings) changes after resolution.
/// Shared by the periodic sync (<see cref="ReferenceSyncBackgroundService"/>) and the admin's "sync now", so both run the same logic.
/// </summary>
public class ReferenceSyncService(
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository,
    ReferenceEnrichmentService enrichmentService,
    ILogger<ReferenceSyncService> logger)
{
    /// <summary>
    /// The most documents one pass refreshes per domain.
    /// The cap is safe because the stalest documents come first (<c>FindStaleAsync</c>),
    /// so what a pass misses leads the next one, and a larger collection rotates over several passes.
    /// It bounds provider traffic per pass, which matters most after a bulk import, when every document is unenriched at once.
    /// </summary>
    private const int MaxDocumentsPerDomainPerPass = 500;

    /// <summary>
    /// Refreshes the references whose <c>LastEnrichedAt</c> is unset or older than <paramref name="staleAfter"/>,
    /// oldest first, up to <see cref="MaxDocumentsPerDomainPerPass"/> per domain.
    /// A failing document is logged and skipped, never aborting the run.
    /// </summary>
    public async Task<ReferenceSyncResultDto> SyncStaleReferencesAsync(TimeSpan staleAfter, Func<ReferenceSyncStage, Task>? onStageChanged = null,
        CancellationToken cancellationToken = default)
    {
        var cutoff = DateTime.UtcNow - staleAfter;
        var result = new ReferenceSyncResultDto();

        // one loop for five domains, each arm supplying only which collection to read and which refresh to run
        await SyncDomainAsync(onStageChanged, ReferenceSyncStage.SyncingTvShows, cutoff,
            tvShowReferenceRepository.FindStaleAsync, enrichmentService.RefreshTvShowReferenceAsync, r => r.Id,
            (checkedCount, updated) => (result.TvShowsChecked, result.TvShowsUpdated) = (checkedCount, updated), cancellationToken);

        await SyncDomainAsync(onStageChanged, ReferenceSyncStage.SyncingMovies, cutoff,
            movieReferenceRepository.FindStaleAsync, enrichmentService.RefreshMovieReferenceAsync, r => r.Id,
            (checkedCount, updated) => (result.MoviesChecked, result.MoviesUpdated) = (checkedCount, updated), cancellationToken);

        await SyncDomainAsync(onStageChanged, ReferenceSyncStage.SyncingBooks, cutoff,
            bookReferenceRepository.FindStaleAsync, enrichmentService.RefreshBookReferenceAsync, r => r.Id,
            (checkedCount, updated) => (result.BooksChecked, result.BooksUpdated) = (checkedCount, updated), cancellationToken);

        await SyncDomainAsync(onStageChanged, ReferenceSyncStage.SyncingVideoGames, cutoff,
            videoGameReferenceRepository.FindStaleAsync, enrichmentService.RefreshVideoGameReferenceAsync, r => r.Id,
            (checkedCount, updated) => (result.VideoGamesChecked, result.VideoGamesUpdated) = (checkedCount, updated), cancellationToken);

        await SyncDomainAsync(onStageChanged, ReferenceSyncStage.SyncingAlbums, cutoff,
            albumReferenceRepository.FindStaleAsync, enrichmentService.RefreshAlbumReferenceAsync, r => r.Id,
            (checkedCount, updated) => (result.AlbumsChecked, result.AlbumsUpdated) = (checkedCount, updated), cancellationToken);

        return result;
    }

    /// <summary>
    /// The sync of one domain: announce the stage, read the stalest page, refresh each document, and report the two counts.
    /// </summary>
    private async Task SyncDomainAsync<TReference>(
        Func<ReferenceSyncStage, Task>? onStageChanged,
        ReferenceSyncStage stage,
        DateTime cutoff,
        Func<DateTime, int, Task<List<TReference>>> findStale,
        Func<TReference, CancellationToken, Task<(TReference Model, bool DataChanged)>> refresh,
        Func<TReference, string?> id,
        Action<int, int> report,
        CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(stage);

        var references = await findStale(cutoff, MaxDocumentsPerDomainPerPass);
        var updated = 0;

        foreach (var reference in references)
        {
            try
            {
                var (_, changed) = await refresh(reference, cancellationToken);
                if (changed) updated++;
            }
            // cancellation is not caught, since a shutdown is not one failing document, and swallowing it would walk the rest of the page against a container being disposed
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Failed to refresh reference {ReferenceId} during {Stage}", id(reference), stage);
            }
        }

        report(references.Count, updated);
    }
}
