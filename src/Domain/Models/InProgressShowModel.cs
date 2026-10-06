using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A TV show in progress, with the last episode known to be watched and the next unwatched one from its TMDB episode guide.
/// Only shows with a reference and a confirmed aired, unwatched episode are reported (see <c>WatchNextService</c>).
/// </summary>
public class InProgressShowModel
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
