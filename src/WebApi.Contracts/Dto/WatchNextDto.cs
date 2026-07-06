using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A TV show with a suggested next episode to watch.
/// </summary>
public class NextEpisodeDto
{
    public required string TvShowId { get; set; }

    public required string TvShowTitle { get; set; }

    public required int NextSeasonNumber { get; set; }

    public required int NextEpisodeNumber { get; set; }

    public DateOnly? LastWatchedAt { get; set; }
}

/// <summary>
/// What to watch next: in-progress shows and movies on the watch list.
/// </summary>
public class WatchNextDto
{
    public List<NextEpisodeDto> NextEpisodes { get; set; } = [];

    public List<MovieDto> MoviesToWatch { get; set; } = [];
}
