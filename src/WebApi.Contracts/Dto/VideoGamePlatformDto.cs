using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One entry per platform a game is tracked on, not one per physical copy.
/// </summary>
public class VideoGamePlatformDto : IOwnedCopyDto
{
    /// <summary>
    /// Platform name, such as "PS5", "Xbox Series X" or "PC".
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
    /// When this entry's <see cref="State"/> was last set to "Completed", filled automatically.
    /// Not to be confused with <see cref="FullyCompletedAt"/>, the platinum date.
    /// </summary>
    public DateOnly? CompletedAt { get; set; }

    /// <summary>
    /// Every recorded run through the game on this platform.
    /// </summary>
    public List<PlaythroughDto> Playthroughs { get; set; } = [];

    /// <summary>
    /// Whether the game was fully completed on this platform, such as a platinum trophy or every achievement.
    /// </summary>
    public bool IsFullyCompleted { get; set; }

    /// <summary>
    /// When the game was fully completed on this platform.
    /// </summary>
    public DateOnly? FullyCompletedAt { get; set; }

    /// <summary>
    /// Price paid, displayed in euros.
    /// </summary>
    public decimal? Price { get; set; }

    /// <summary>
    /// Where this copy was bought: store, site, marketplace seller.
    /// </summary>
    public string? Vendor { get; set; }

    /// <summary>
    /// When this copy was acquired, if recorded.
    /// </summary>
    public DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode.
    /// </summary>
    public string? Reference { get; set; }

    /// <summary>
    /// The store's product or edition text for this copy ("Grand Theft Auto V : Édition Premium"), as opposed to the game's title.
    /// </summary>
    public string? ProductName { get; set; }
}
