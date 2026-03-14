using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class TvShowModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? LastEpisodeSeen { get; set; }

    public string? ImdbPageId { get; set; }

    public string? AllocineId { get; set; }

    public DateOnly? FinishedAt { get; set; }
}
