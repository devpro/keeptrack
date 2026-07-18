using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One entry per platform a game is tracked on for a given tenant - not one entry per physical copy.
/// Owning two PS5 discs of the same game is still a single entry with <see cref="Platform"/> "PS5".
/// <see cref="IsFullyCompleted"/>/<see cref="FullyCompletedAt"/> ("platinum"/100%) live here rather than
/// on <see cref="VideoGameModel"/> or on a single <see cref="Playthroughs"/> entry, because full
/// completion is a per-platform fact - a PS5 platinum says nothing about Xbox/PC progress on the same game.
/// </summary>
public class VideoGamePlatformModel
{
    public required string Platform { get; set; }

    public CopyType CopyType { get; set; }

    public string State { get; set; } = "";

    /// <summary>
    /// The date this entry's <see cref="State"/> was last set to "Completed" - auto-populated, not to be
    /// confused with <see cref="FullyCompletedAt"/>/<see cref="IsFullyCompleted"/> (the platinum/100% flag).
    /// </summary>
    public DateOnly? CompletedAt { get; set; }

    public List<PlaythroughModel> Playthroughs { get; set; } = [];

    public bool IsFullyCompleted { get; set; }

    public DateOnly? FullyCompletedAt { get; set; }

    /// <summary>
    /// Price paid for this copy. Stored currency-agnostic and displayed in the user's currency - the same
    /// convention as <see cref="OwnedVersionModel.Price"/>, which this platform entry otherwise stands in
    /// for (see this class's own doc comment).
    /// </summary>
    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    /// <summary>When this copy was acquired, if the user remembers/cares to record it.</summary>
    public DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode, shelf location...
    /// Unrelated to the reference-data <c>ReferenceId</c> concept.
    /// </summary>
    public string? Reference { get; set; }
}
