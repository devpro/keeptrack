using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

// this service reasons about the Domain status enum (the tenant model's own State), not the DTO one that the
// Contracts.Dto global using also brings into scope - same disambiguation Amazon/Generic import controllers need.
using TvShowStatus = Keeptrack.Domain.Models.TvShowStatus;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Reopens finished TV shows once a new episode airs. Completing a show can't be a permanent decision -
/// when a tenant marks a show <see cref="TvShowStatus.Finished"/> there's no way to know whether a further
/// season will ever be announced, so the only deterministic approach is to accept "finished" as of now and
/// let a regular pass reconcile it against the (independently kept-fresh) reference episode guide.
/// If a linked reference now lists an aired episode beyond the tenant's last-watched one, the show is flipped
/// back to <see cref="TvShowStatus.Current"/> so it resurfaces in Watch Next.
///
/// Runs right after <see cref="ReferenceSyncService"/> in the same background tick (and the admin's on-demand
/// "sync now"), so it always reconciles against the just-updated episode lists rather than stale data.
/// It's the tenant-data counterpart to <see cref="ReferenceSyncService"/>'s shared-reference refresh, kept a
/// separate service so that one's charter stays "keep the owner-less reference collections fresh" only.
///
/// Only <see cref="TvShowStatus.Finished"/> shows are touched. <see cref="TvShowStatus.Stopped"/> and an unset
/// status both mean the tenant deliberately isn't tracking the show, so a new season must never reopen them -
/// this is enforced at the query (<see cref="ITvShowRepository.FindFinishedLinkedShowsAsync"/>), so no other
/// state is ever a candidate here.
/// </summary>
public class TvShowStatusReconciliationService(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    ILogger<TvShowStatusReconciliationService> logger)
{
    /// <summary>
    /// Re-checks every finished, reference-linked show across all tenants and reopens (to
    /// <see cref="TvShowStatus.Current"/>) the ones whose reference guide now lists an aired episode after the
    /// last one watched. Returns how many shows were reopened. A failure on one show is logged and skipped
    /// rather than aborting the whole pass, mirroring <see cref="ReferenceSyncService"/>'s per-document resilience.
    /// </summary>
    public async Task<int> ReconcileFinishedShowsAsync(CancellationToken cancellationToken = default)
    {
        var finishedShows = await tvShowRepository.FindFinishedLinkedShowsAsync();
        if (finishedShows.Count == 0) return 0;

        var today = DateOnly.FromDateTime(DateTime.Today);

        // one batched reference lookup for the whole pass, keyed by reference id (a reference is shared, so
        // many shows across tenants can point at the same document).
        var referencesById = (await tvShowReferenceRepository.FindByIdsAsync(
                finishedShows.Select(s => s.ReferenceId!).Distinct().ToList()))
            .ToDictionary(r => r.Id!);

        var reopened = 0;

        // episodes are owner-scoped, so re-check one tenant at a time and reuse the same batched read Watch Next uses.
        foreach (var showsByOwner in finishedShows.GroupBy(s => s.OwnerId))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var episodesByShow = (await episodeRepository.FindByShowIdsAsync(
                    showsByOwner.Key, showsByOwner.Select(s => s.Id!).ToList()))
                .GroupBy(e => e.TvShowId)
                .ToDictionary(g => g.Key, g => g.ToList());

            foreach (var show in showsByOwner)
            {
                try
                {
                    if (await TryReopenAsync(show, episodesByShow, referencesById, today)) reopened++;
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to reconcile status for TV show {TvShowId} (owner {OwnerId})", show.Id, show.OwnerId);
                }
            }
        }

        if (reopened > 0) logger.LogInformation("Status reconciliation: reopened {Count} finished show(s) as current.", reopened);
        return reopened;
    }

    private async Task<bool> TryReopenAsync(
        TvShowModel show,
        IReadOnlyDictionary<string, List<EpisodeModel>> episodesByShow,
        IReadOnlyDictionary<string, TvShowReferenceModel> referencesById,
        DateOnly today)
    {
        // no recorded episodes means there's no "last watched" to compare against - can't tell whether a
        // newer episode exists, so leave the show alone rather than guess (same "don't guess" rule as Watch Next).
        if (!episodesByShow.TryGetValue(show.Id!, out var episodes) || episodes.Count == 0) return false;
        if (!referencesById.TryGetValue(show.ReferenceId!, out var reference)) return false;

        var lastWatched = episodes
            .OrderByDescending(e => e.SeasonNumber)
            .ThenByDescending(e => e.EpisodeNumber)
            .First();

        if (WatchNextService.FindNextAiredEpisode(lastWatched.SeasonNumber, lastWatched.EpisodeNumber, reference, today) is null) return false;

        show.State = TvShowStatus.Current;
        await tvShowRepository.UpdateAsync(show.Id!, show, show.OwnerId);
        return true;
    }
}
