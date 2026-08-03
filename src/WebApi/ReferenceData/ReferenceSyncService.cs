using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps the shared reference collections up to date with TMDB after their initial resolution -
/// TMDB data (episode air dates, genres, posters, cast) isn't static, so a show/movie resolved months ago can drift out of date otherwise.
/// Shared by the periodic background sync (<see cref="ReferenceSyncBackgroundService"/>) and the admin's on-demand "sync now" action, so both go through the exact same logic.
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
    /// The most documents one pass refreshes per domain. A cap is only safe because the query returns the
    /// stalest documents first (see <c>FindStaleAsync</c>): whatever a pass doesn't reach is at the front of
    /// the next one, so nothing starves - it just means a collection larger than this rotates over several
    /// passes rather than all in one. What it buys is a bounded, predictable amount of provider traffic per
    /// pass instead of "however many happened to be stale", which matters most on the very first pass after a
    /// bulk import, when every document is unenriched at once.
    /// </summary>
    private const int MaxDocumentsPerDomainPerPass = 500;

    /// <summary>
    /// Refreshes the stalest reference documents whose <c>LastEnrichedAt</c> is older than <paramref name="staleAfter"/> (or unset), oldest first, up to <see cref="MaxDocumentsPerDomainPerPass"/> per domain.
    /// A failure on one document is logged and skipped rather than aborting the whole run - one bad TMDB response shouldn't block every other show/movie from being checked.
    /// </summary>
    public async Task<ReferenceSyncResultDto> SyncStaleReferencesAsync(TimeSpan staleAfter, Func<ReferenceSyncStage, Task>? onStageChanged = null,
        CancellationToken cancellationToken = default)
    {
        var cutoff = DateTime.UtcNow - staleAfter;
        var result = new ReferenceSyncResultDto();

        // one loop, five domains: each arm supplies only the two things that genuinely differ - which
        // collection to read and which refresh to run - so a sixth domain is a call, never another copy.
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
    /// The whole per-domain sync: announce the stage, read the stalest page, refresh each document, and report
    /// the two counts. Every domain ran a byte-for-byte copy of this before, five times over.
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
            // cancellation is deliberately not caught here: one failing document must never abort the run, but
            // a shutdown is not one failing document - swallowing it would walk the rest of the page calling a
            // container that is already being disposed.
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Failed to refresh reference {ReferenceId} during {Stage}", id(reference), stage);
            }
        }

        report(references.Count, updated);
    }
}
