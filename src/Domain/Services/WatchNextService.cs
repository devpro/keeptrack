using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes, for each in-progress TV show, whether there is a confirmed unseen episode to watch next.
/// </summary>
public static class WatchNextService
{
    /// <summary>
    /// A show appears only when marked <see cref="Domain.Models.TvShowStatus.Current"/> <b>and</b> its TMDB episode guide (<paramref name="referencesByShowId"/>) confirms an aired episode after the last one watched.
    /// Without a reference there is no guide to tell whether another episode exists, so an unlinked show is excluded rather than guessed at.
    /// </summary>
    public static List<InProgressShowModel> ComputeInProgressShows(
        IEnumerable<TvShowModel> shows,
        IEnumerable<EpisodeModel> episodes,
        IReadOnlyDictionary<string, TvShowReferenceModel> referencesByShowId)
    {
        var currentShows = shows.Where(s => s.State == Domain.Models.TvShowStatus.Current).ToDictionary(s => s.Id!);
        var today = DateOnly.FromDateTime(DateTime.Today);

        return episodes
            .Where(e => currentShows.ContainsKey(e.TvShowId))
            .GroupBy(e => e.TvShowId)
            .Select(group =>
            {
                var show = currentShows[group.Key];
                var lastWatched = group
                    .OrderByDescending(e => e.SeasonNumber)
                    .ThenByDescending(e => e.EpisodeNumber)
                    .First();

                if (!referencesByShowId.TryGetValue(group.Key, out var reference)) return null;

                var nextEpisode = FindNextAiredEpisode(lastWatched.SeasonNumber, lastWatched.EpisodeNumber, reference, today);
                if (nextEpisode is null) return null;

                return new InProgressShowModel
                {
                    TvShowId = show.Id!,
                    TvShowTitle = show.Title,
                    LastSeasonNumber = lastWatched.SeasonNumber,
                    LastEpisodeNumber = lastWatched.EpisodeNumber,
                    LastWatchedAt = lastWatched.WatchedAt,
                    NextSeasonNumber = nextEpisode.SeasonNumber,
                    NextEpisodeNumber = nextEpisode.EpisodeNumber,
                    NextEpisodeTitle = nextEpisode.Title
                };
            })
            .Where(model => model is not null)
            .Select(model => model!)
            .OrderByDescending(n => n.LastWatchedAt)
            .ToList();
    }

    /// <summary>
    /// The first episode of the guide after <paramref name="lastWatchedSeason"/> and <paramref name="lastWatchedEpisode"/> that has aired (<see cref="ReferenceEpisodeModel.AirDate"/> unset or before <paramref name="today"/>), or null.
    /// Ordered by (season, episode), not by title or air date.
    /// <see cref="ComputeInProgressShows"/> shows it as the next episode, and the sync reopens a finished show as current when there is one.
    /// </summary>
    public static ReferenceEpisodeModel? FindNextAiredEpisode(int lastWatchedSeason, int lastWatchedEpisode, TvShowReferenceModel reference, DateOnly today) =>
        reference.Episodes
            .Where(e => e.SeasonNumber > lastWatchedSeason
                        || (e.SeasonNumber == lastWatchedSeason && e.EpisodeNumber > lastWatchedEpisode))
            .Where(e => e.AirDate is null || e.AirDate <= today)
            .OrderBy(e => e.SeasonNumber)
            .ThenBy(e => e.EpisodeNumber)
            .FirstOrDefault();

    /// <summary>
    /// A movie flagged "want to watch" and since marked seen leaves the list.
    /// Marking a movie seen does not clear the flag, so it is filtered here rather than trusting the flag never to go stale.
    /// </summary>
    public static List<MovieModel> FilterMoviesToWatch(IEnumerable<MovieModel> movies) =>
        movies.Where(m => m.FirstSeenAt is null).ToList();
}
