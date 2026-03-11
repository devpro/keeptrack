using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class VideoGameModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Platform { get; set; }

    public DateOnly? ReleasedAt { get; set; }

    public required string State { get; set; }

    public DateOnly? FinishedAt { get; set; }
}
