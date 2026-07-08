using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A TV show in progress, with the last episode Keeptrack knows was watched and the next confirmed-unseen
/// one from its TMDB episode guide. Only shows with a resolved reference and a confirmed aired-but-unwatched
/// episode are reported at all - see WatchNextService.
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
