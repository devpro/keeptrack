using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A TV show in progress, with the last episode Keeptrack knows was watched and the next confirmed-unseen
/// one from its TMDB episode guide. Only shows with a resolved reference and a confirmed aired-but-unwatched
/// episode are reported at all - see WatchNextService in WebApi.
/// </summary>
public class InProgressShowDto
{
    public required string TvShowId { get; set; }

    public required string TvShowTitle { get; set; }

    public required int LastSeasonNumber { get; set; }

    public required int LastEpisodeNumber { get; set; }

    public DateOnly? LastWatchedAt { get; set; }

    public required int NextSeasonNumber { get; set; }

    public required int NextEpisodeNumber { get; set; }

    public required string NextEpisodeTitle { get; set; }
}

/// <summary>
/// What to watch next: in-progress shows and movies on the watch list.
/// </summary>
public class WatchNextDto
{
    public List<InProgressShowDto> InProgressShows { get; set; } = [];

    public List<MovieDto> MoviesToWatch { get; set; } = [];
}
