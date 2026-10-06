using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One entry per platform a tenant tracks a game on, not one per physical copy: two PS5 discs of a game are one "PS5" entry.
/// <see cref="IsFullyCompleted"/> and <see cref="FullyCompletedAt"/> (platinum, 100%) live here rather than on the game or a playthrough, since full completion is per platform.
/// A PS5 platinum says nothing about progress on Xbox or PC.
/// </summary>
public class VideoGamePlatformModel
{
    public required string Platform { get; set; }

    public CopyType CopyType { get; set; }

    public string State { get; set; } = "";

    /// <summary>
    /// When this entry's <see cref="State"/> was last set to "Completed", filled automatically.
    /// Not to be confused with <see cref="FullyCompletedAt"/> and <see cref="IsFullyCompleted"/>, the platinum flag.
    /// </summary>
    public DateOnly? CompletedAt { get; set; }

    public List<PlaythroughModel> Playthroughs { get; set; } = [];

    public bool IsFullyCompleted { get; set; }

    public DateOnly? FullyCompletedAt { get; set; }

    /// <summary>
    /// Price paid for this copy, stored without a currency like <see cref="OwnedVersionModel.Price"/>.
    /// </summary>
    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode, shelf location.
    /// Unrelated to the reference data's <c>ReferenceId</c>.
    /// </summary>
    public string? Reference { get; set; }

    /// <summary>
    /// The store's product or edition text for this copy ("Grand Theft Auto V : Édition Premium"), as opposed to the game's <see cref="VideoGameModel.Title"/>.
    /// The video game import fills it from its "Product Name" column.
    /// </summary>
    public string? ProductName { get; set; }
}
