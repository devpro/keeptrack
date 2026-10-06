using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One owned copy of a tracked item with its optional purchase details.
/// An item is owned when it has at least one copy.
/// </summary>
public class OwnedVersionDto : IOwnedCopyDto
{
    /// <summary>
    /// Physical or digital copy, physical by default.
    /// </summary>
    public CopyType CopyType { get; set; }

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
    /// The store's product or edition text for this copy (a retailer's listing title), distinct from the item's title.
    /// </summary>
    public string? ProductName { get; set; }
}
