using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class EpisodeModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string TvShowId { get; set; }

    public required int SeasonNumber { get; set; }

    public required int EpisodeNumber { get; set; }

    public DateOnly? WatchedAt { get; set; }

    public string? Notes { get; set; }
}
