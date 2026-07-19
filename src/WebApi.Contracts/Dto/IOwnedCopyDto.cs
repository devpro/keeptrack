using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One owned/tracked copy's purchase details, shared by <see cref="OwnedVersionDto"/> (movie/TV show/book/album)
/// and <see cref="VideoGamePlatformDto"/> (whose per-platform entry is itself the copy). Lets the shared
/// OwnedVersionFields component edit either DTO through one set of fields.
/// </summary>
public interface IOwnedCopyDto
{
    /// <summary>
    /// Physical or digital copy - physical by default.
    /// </summary>
    CopyType CopyType { get; set; }

    /// <summary>
    /// Price paid, in the user's own currency (currently always displayed as euros).
    /// </summary>
    decimal? Price { get; set; }

    /// <summary>
    /// When this copy was acquired, if recorded.
    /// </summary>
    DateOnly? AcquiredAt { get; set; }

    /// <summary>
    /// Where this copy was bought (store, site, marketplace seller...).
    /// </summary>
    string? Vendor { get; set; }

    /// <summary>
    /// Free-text reference for this copy: edition name, order number, barcode...
    /// </summary>
    string? Reference { get; set; }
}
