using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.WatchNext;

/// <summary>
/// Computes, for each in-progress TV show, the last episode Keeptrack knows was watched.
/// </summary>
public class WatchNextService
{
    /// <summary>
    /// For every show that has at least one watched episode and isn't finished, reports the highest
    /// (season, episode) watched so far. Deliberately doesn't propose a "next" episode: without
    /// episode-guide data, Keeptrack can't tell whether a further episode exists yet, so guessing one
    /// (e.g. "+1") can claim a show still has more to watch when it's actually fully caught up.
    /// </summary>
    public List<InProgressShowDto> ComputeInProgressShows(IEnumerable<TvShowModel> shows, IEnumerable<EpisodeModel> episodes)
    {
        var inProgressShows = shows
            .Where(s => s.Status != Domain.Models.TvShowStatus.Finished && s.Status != Domain.Models.TvShowStatus.Stopped)
            .ToDictionary(s => s.Id!);

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
                return new InProgressShowDto
                {
                    TvShowId = show.Id!,
                    TvShowTitle = show.Title,
                    LastSeasonNumber = lastWatched.SeasonNumber,
                    LastEpisodeNumber = lastWatched.EpisodeNumber,
                    LastWatchedAt = lastWatched.WatchedAt
                };
            })
            .OrderByDescending(n => n.LastWatchedAt)
            .ToList();
    }
}
