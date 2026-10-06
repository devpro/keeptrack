using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One run through a game: the base playthrough, an NG+ replay, a speedrun, or any other attempt.
/// <see cref="Label"/> is free text, since replays do not fit a closed set (NG+1, NG+2, a run just for fun).
/// <see cref="CompletedAt"/> is optional, so an in-progress or abandoned run can still be logged.
/// </summary>
public class PlaythroughModel
{
    public required string Label { get; set; }

    public DateOnly? CompletedAt { get; set; }
}
