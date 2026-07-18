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

    /// <summary>
    /// Price paid, in the user's own currency (currently always displayed as euros).
    /// </summary>
    public decimal? Price { get; set; }

    /// <summary>
    /// Where this copy was bought (store, site, marketplace seller...).
    /// </summary>
    public string? Vendor { get; set; }

    /// <summary>
    /// When this copy was acquired, if recorded.
    /// </summary>
    public DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode...
    /// </summary>
    public string? Reference { get; set; }
}
