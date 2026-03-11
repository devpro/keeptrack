using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Video Game data transfer object.
/// </summary>
public class VideoGameDto : IHasId
{
    /// <summary>
    /// Video Game ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Video Game title.
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Latest plaform the game has been played on.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Released date.
    /// </summary>
    public DateOnly? ReleasedAt { get; set; }

    /// <summary>
    /// Current payling state.
    /// </summary>
    public string? State { get; set; }

    /// <summary>
    /// Finished date.
    /// </summary>
    public DateOnly? FinishedAt { get; set; }
}
