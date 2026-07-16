using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One entry per platform a game is tracked on - not one entry per physical copy.
/// </summary>
public class VideoGamePlatformDto
{
    /// <summary>
    /// Platform name (e.g. "PS5", "Xbox Series X", "PC").
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Whether this is a physical or digital copy.
    /// </summary>
    public CopyType CopyType { get; set; }

    /// <summary>
    /// Current playing state for this platform entry.
    /// </summary>
    public string? State { get; set; }

    /// <summary>
    /// Every recorded run through the game on this platform.
    /// </summary>
    public List<PlaythroughDto> Playthroughs { get; set; } = [];

    /// <summary>
    /// Whether the game has been fully completed (e.g. platinum trophy, 1000/1000 achievements) on this platform.
    /// </summary>
    public bool IsFullyCompleted { get; set; }

    /// <summary>
    /// When the game was fully completed on this platform.
    /// </summary>
    public DateOnly? FullyCompletedAt { get; set; }
}
