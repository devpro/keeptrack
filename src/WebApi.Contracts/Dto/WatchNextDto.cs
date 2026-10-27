using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A TV show in progress, with the last episode known to be watched and the next unwatched one from its TMDB episode guide.
/// Only shows with a reference and a confirmed aired, unwatched episode are reported (see <c>WatchNextService</c>).
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

    /// <summary>
    /// The show's cover URL, hydrated server side from the reference that confirmed the next episode.
    /// </summary>
    public string? ImageUrl { get; set; }
}

/// <summary>
/// What to watch next: in-progress shows and movies on the watch list.
/// </summary>
public class WatchNextDto
{
    public List<InProgressShowDto> InProgressShows { get; set; } = [];

    public List<MovieDto> MoviesToWatch { get; set; } = [];
}
