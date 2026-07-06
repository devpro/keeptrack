using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.WatchNext;

/// <summary>
/// Computes, for each in-progress TV show, the next episode to watch.
/// </summary>
public class WatchNextService
{
    /// <summary>
    /// For every show that has at least one watched episode and isn't finished, proposes the episode
    /// right after the highest (season, episode) watched so far.
    /// </summary>
    public List<NextEpisodeDto> ComputeNextEpisodes(IEnumerable<TvShowModel> shows, IEnumerable<EpisodeModel> episodes)
    {
        var inProgressShows = shows.Where(s => s.FinishedAt is null).ToDictionary(s => s.Id!);

        return episodes
            .Where(e => inProgressShows.ContainsKey(e.TvShowId))
            .GroupBy(e => e.TvShowId)
            .Select(group =>
            {
                var show = inProgressShows[group.Key];
                var lastWatched = group
                    .OrderByDescending(e => e.SeasonNumber)
                    .ThenByDescending(e => e.EpisodeNumber)
                    .First();
                return new NextEpisodeDto
                {
                    TvShowId = show.Id!,
                    TvShowTitle = show.Title,
                    NextSeasonNumber = lastWatched.SeasonNumber,
                    NextEpisodeNumber = lastWatched.EpisodeNumber + 1,
                    LastWatchedAt = lastWatched.WatchedAt
                };
            })
            .OrderByDescending(n => n.LastWatchedAt)
            .ToList();
    }
}
