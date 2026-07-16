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
    /// Refreshes every reference document whose <c>LastEnrichedAt</c> is older than <paramref name="staleAfter"/> (or unset).
    /// A failure on one document is logged and skipped rather than aborting the whole run - one bad TMDB response shouldn't block every other show/movie from being checked.
    /// </summary>
    public async Task<ReferenceSyncResultDto> SyncStaleReferencesAsync(TimeSpan staleAfter, Func<ReferenceSyncStage, Task>? onStageChanged = null,
        CancellationToken cancellationToken = default)
    {
        var cutoff = DateTime.UtcNow - staleAfter;
        var result = new ReferenceSyncResultDto();

        await SyncTvShowAsync(onStageChanged, cutoff, result, cancellationToken);

        await SyncMovieAsync(onStageChanged, cutoff, result, cancellationToken);

        await SyncBookAsync(onStageChanged, cutoff, result, cancellationToken);

        await SyncVideoGameAsync(onStageChanged, cutoff, result, cancellationToken);

        await SyncAlbumAsync(onStageChanged, cutoff, result, cancellationToken);

        return result;
    }

    private async Task SyncTvShowAsync(Func<ReferenceSyncStage, Task>? onStageChanged, DateTime cutoff, ReferenceSyncResultDto result, CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(ReferenceSyncStage.SyncingTvShows);
        foreach (var reference in await tvShowReferenceRepository.FindAllAsync())
        {
            if (reference.LastEnrichedAt is not null && reference.LastEnrichedAt > cutoff) continue;

            result.TvShowsChecked++;
            try
            {
                var (_, changed) = await enrichmentService.RefreshTvShowReferenceAsync(reference, cancellationToken);
                if (changed) result.TvShowsUpdated++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to refresh TV show reference {ReferenceId}", reference.Id);
            }
        }
    }

    private async Task SyncMovieAsync(Func<ReferenceSyncStage, Task>? onStageChanged, DateTime cutoff, ReferenceSyncResultDto result, CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(ReferenceSyncStage.SyncingMovies);
        foreach (var reference in await movieReferenceRepository.FindAllAsync())
        {
            if (reference.LastEnrichedAt is not null && reference.LastEnrichedAt > cutoff) continue;

            result.MoviesChecked++;
            try
            {
                var (_, changed) = await enrichmentService.RefreshMovieReferenceAsync(reference, cancellationToken);
                if (changed) result.MoviesUpdated++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to refresh movie reference {ReferenceId}", reference.Id);
            }
        }
    }

    private async Task SyncBookAsync(Func<ReferenceSyncStage, Task>? onStageChanged, DateTime cutoff, ReferenceSyncResultDto result, CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(ReferenceSyncStage.SyncingBooks);
        foreach (var reference in await bookReferenceRepository.FindAllAsync())
        {
            if (reference.LastEnrichedAt is not null && reference.LastEnrichedAt > cutoff) continue;

            result.BooksChecked++;
            try
            {
                var (_, changed) = await enrichmentService.RefreshBookReferenceAsync(reference, cancellationToken);
                if (changed) result.BooksUpdated++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to refresh book reference {ReferenceId}", reference.Id);
            }
        }
    }

    private async Task SyncVideoGameAsync(Func<ReferenceSyncStage, Task>? onStageChanged, DateTime cutoff, ReferenceSyncResultDto result, CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(ReferenceSyncStage.SyncingVideoGames);
        foreach (var reference in await videoGameReferenceRepository.FindAllAsync())
        {
            if (reference.LastEnrichedAt is not null && reference.LastEnrichedAt > cutoff) continue;

            result.VideoGamesChecked++;
            try
            {
                var (_, changed) = await enrichmentService.RefreshVideoGameReferenceAsync(reference, cancellationToken);
                if (changed) result.VideoGamesUpdated++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to refresh video game reference {ReferenceId}", reference.Id);
            }
        }
    }

    private async Task SyncAlbumAsync(Func<ReferenceSyncStage, Task>? onStageChanged, DateTime cutoff, ReferenceSyncResultDto result, CancellationToken cancellationToken)
    {
        if (onStageChanged is not null) await onStageChanged(ReferenceSyncStage.SyncingAlbums);
        foreach (var reference in await albumReferenceRepository.FindAllAsync())
        {
            if (reference.LastEnrichedAt is not null && reference.LastEnrichedAt > cutoff) continue;

            result.AlbumsChecked++;
            try
            {
                var (_, changed) = await enrichmentService.RefreshAlbumReferenceAsync(reference, cancellationToken);
                if (changed) result.AlbumsUpdated++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to refresh album reference {ReferenceId}", reference.Id);
            }
        }
    }
}
