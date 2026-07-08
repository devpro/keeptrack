using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One recorded run through a game - the base playthrough, an NG+ replay, a speedrun, or any other
/// attempt worth logging.
/// </summary>
public class PlaythroughDto
{
    /// <summary>
    /// Free-text label for this run (e.g. "First run", "NG+1", "Speedrun for fun").
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// When this run was completed. Unset if still in progress or abandoned.
    /// </summary>
    public DateOnly? CompletedAt { get; set; }
}
