using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Platform { get; set; }

    public required string State { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public DateOnly? FinishedAt { get; set; }
}
