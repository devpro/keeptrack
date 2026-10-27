using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// An owned copy's purchase details, shared by <see cref="OwnedVersionDto"/> and <see cref="VideoGamePlatformDto"/>, whose platform entry is the copy.
/// The shared OwnedVersionFields component edits either through one set of fields.
/// </summary>
public interface IOwnedCopyDto
{
    /// <summary>
    /// Physical or digital copy, physical by default.
    /// </summary>
    CopyType CopyType { get; set; }

    /// <summary>
    /// Price paid, displayed in euros.
    /// </summary>
    decimal? Price { get; set; }

    /// <summary>
    /// When this copy was acquired, if recorded.
    /// </summary>
    DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Where this copy was bought: store, site, marketplace seller.
    /// </summary>
    string? Vendor { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode.
    /// </summary>
    string? Reference { get; set; }
}
