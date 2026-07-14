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
    /// A show only appears here if it's marked <see cref="Domain.Models.TvShowStatus.Current"/>
    /// AND has a resolved TMDB episode guide (<paramref name="referencesByShowId"/>) confirming an aired episode exists after the last one watched.
    /// Without a reference, Keeptrack has no episode-guide data and can't tell whether a further episode actually exists (the show might already be fully caught up) -
    /// so unlinked shows are excluded rather than guessed at, the same "don't guess" principle as before, now enforced by data.
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

                var nextEpisode = reference.Episodes
                    .Where(e => e.SeasonNumber > lastWatched.SeasonNumber
                                || (e.SeasonNumber == lastWatched.SeasonNumber && e.EpisodeNumber > lastWatched.EpisodeNumber))
                    .Where(e => e.AirDate is null || e.AirDate <= today)
                    .OrderBy(e => e.SeasonNumber)
                    .ThenBy(e => e.EpisodeNumber)
                    .FirstOrDefault();
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
    /// A movie flagged "want to watch" that has since been marked seen shouldn't linger in the watchlist -
    /// mirrors <c>MovieTrackingEventsCsvParser</c>'s "towatch" handling, which never flags an already-watched movie in the first place.
    /// Toggling "want to watch" directly on a movie's own detail page doesn't clear the flag on watch, so this is filtered here rather than relying on the flag never going stale.
    /// </summary>
    public static List<MovieModel> FilterMoviesToWatch(IEnumerable<MovieModel> movies) =>
        movies.Where(m => m.FirstSeenAt is null).ToList();
}
