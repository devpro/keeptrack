using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One run through a game: the base playthrough, an NG+ replay, a speedrun, or any other attempt worth logging.
/// </summary>
public class PlaythroughDto
{
    /// <summary>
    /// Free-text label for this run, such as "First run" or "NG+1".
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// When this run was completed, unset while in progress or when abandoned.
    /// </summary>
    public DateOnly? CompletedAt { get; set; }
}
