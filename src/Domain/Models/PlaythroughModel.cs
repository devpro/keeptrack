using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One recorded run through a game - the base playthrough, an NG+ replay, a speedrun, or any other
/// attempt the tenant wants to log. <see cref="Label"/> is free text rather than a fixed enum because
/// replays don't fit a closed set (NG+1, NG+2, a side-run "just for fun", ...). <see cref="CompletedAt"/>
/// is optional so an in-progress or abandoned run can still be logged.
/// </summary>
public class PlaythroughModel
{
    public required string Label { get; set; }

    public DateOnly? CompletedAt { get; set; }
}
