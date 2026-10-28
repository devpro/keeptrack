using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

// the Domain status enum, not the Contracts one the global using also imports
using TvShowStatus = Keeptrack.Domain.Models.TvShowStatus;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Reopens finished TV shows once a new episode airs.
/// A tenant marking a show <see cref="TvShowStatus.Finished"/> cannot know whether another season will come,
/// so "finished" holds as of now and a regular pass checks it against the episode guide.
/// When the linked reference lists an aired episode after the last one watched, the show goes back to <see cref="TvShowStatus.Current"/> and reappears in Watch Next.
///
/// <see cref="ReferenceSyncService"/> runs it right after the TV domain, in the same tick or "sync now", so it checks the freshly updated guides.
/// It works on tenant data, kept apart from the reference refresh, whose only charter is the shared collections.
///
/// Only finished shows are touched.
/// <see cref="TvShowStatus.Stopped"/> and unset both mean the tenant stopped tracking on purpose,
/// so the query (<see cref="ITvShowRepository.FindFinishedLinkedShowsAsync"/>) never returns them.
/// </summary>
public class TvShowStatusReconciliationService(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    ILogger<TvShowStatusReconciliationService> logger)
{
    /// <summary>
    /// Checks every finished, linked show of every tenant again,
    /// and reopens as <see cref="TvShowStatus.Current"/> those whose guide lists an aired episode after the last one watched.
    /// Returns how many shows were reopened.
    /// A failing show is logged and skipped, like a document in <see cref="ReferenceSyncService"/>.
    /// </summary>
    public async Task<int> ReconcileFinishedShowsAsync(CancellationToken cancellationToken = default)
    {
        var finishedShows = await tvShowRepository.FindFinishedLinkedShowsAsync();
        if (finishedShows.Count == 0) return 0;

        var today = DateOnly.FromDateTime(DateTime.Today);

        // one batched lookup for the pass, keyed by reference id, since shows of many tenants can share a reference
        var referencesById = (await tvShowReferenceRepository.FindByIdsAsync(
                finishedShows.Select(s => s.ReferenceId!).Distinct().ToList()))
            .ToDictionary(r => r.Id!);

        var reopened = 0;

        // episodes are owner-scoped, so tenants are checked one at a time with Watch Next's batched read
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
        // without recorded episodes there is no last watched to compare, so the show is left alone rather than guessed at
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
