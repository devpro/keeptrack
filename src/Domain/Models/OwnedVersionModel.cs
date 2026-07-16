using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One owned copy of a tracked item (movie, TV show, book, album) with its optional purchase details.
/// An item is "owned" exactly when it has at least one version - there is deliberately no separate
/// stored owned flag to drift out of sync with this list. Video games don't use this type: their
/// per-platform entries (<see cref="VideoGamePlatformModel"/>, each with its own <see cref="CopyType"/>)
/// already are their copies, so ownership derives from those instead.
/// </summary>
public class OwnedVersionModel
{
    public CopyType CopyType { get; set; }

    /// <summary>
    /// Price paid. Stored currency-agnostic and displayed in the user's currency (hardcoded to euros
    /// for now; a per-user currency setting in the profile is a possible future addition).
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
