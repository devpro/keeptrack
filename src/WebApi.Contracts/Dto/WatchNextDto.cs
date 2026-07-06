using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A TV show in progress, with the last episode Keeptrack knows was watched. Deliberately does not
/// guess a "next" episode number: Keeptrack has no episode-guide data, so it has no way to know
/// whether a further episode actually exists (the show might already be fully caught up).
/// </summary>
public class InProgressShowDto
{
    public required string TvShowId { get; set; }

    public required string TvShowTitle { get; set; }

    public required int LastSeasonNumber { get; set; }

    public required int LastEpisodeNumber { get; set; }

    public DateOnly? LastWatchedAt { get; set; }
}

/// <summary>
/// What to watch next: in-progress shows and movies on the watch list.
/// </summary>
public class WatchNextDto
{
    public List<InProgressShowDto> InProgressShows { get; set; } = [];

    public List<MovieDto> MoviesToWatch { get; set; } = [];
}
