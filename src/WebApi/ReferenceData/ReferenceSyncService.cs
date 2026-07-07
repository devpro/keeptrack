using System;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps the shared reference collections up to date with TMDB after their initial resolution - TMDB
/// data (episode air dates, genres, posters, cast) isn't static, so a show/movie resolved months ago can
/// drift out of date otherwise. Shared by the periodic background sync (<see cref="ReferenceSyncBackgroundService"/>)
/// and the admin's on-demand "sync now" action, so both go through the exact same logic.
/// </summary>
public class ReferenceSyncService(
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ReferenceEnrichmentService enrichmentService,
    ILogger<ReferenceSyncService> logger)
{
    /// <summary>
    /// Refreshes every reference document whose <c>LastEnrichedAt</c> is older than <paramref name="staleAfter"/>
    /// (or unset). A failure on one document is logged and skipped rather than aborting the whole run - one
    /// bad TMDB response shouldn't block every other show/movie from being checked.
    /// </summary>
    public async Task<ReferenceSyncResultDto> SyncStaleReferencesAsync(TimeSpan staleAfter, CancellationToken cancellationToken = default)
    {
        var cutoff = DateTime.UtcNow - staleAfter;
        var result = new ReferenceSyncResultDto();

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

        return result;
    }
}
