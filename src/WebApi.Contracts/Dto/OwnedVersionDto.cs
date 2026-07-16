using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One owned copy of a tracked item (movie, TV show, book, album) with its optional purchase details.
/// An item is considered owned when it has at least one version.
/// </summary>
public class OwnedVersionDto
{
    /// <summary>
    /// Physical or digital copy - physical by default.
    /// </summary>
    public CopyType CopyType { get; set; }

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
