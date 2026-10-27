using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One owned copy of a tracked item, with its optional purchase details.
/// An item is owned exactly when it has at least one copy, so no stored flag can drift from this list.
/// Video games do not use it: their <see cref="VideoGamePlatformModel"/> entries are their copies, declaring the same purchase fields alongside their platform fields.
/// </summary>
public class OwnedVersionModel
{
    public CopyType CopyType { get; set; }

    /// <summary>
    /// Price paid, stored without a currency and displayed in euros.
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
    /// The store's product or edition text for this copy (a retailer's listing title), distinct from the item's title.
    /// </summary>
    public string? ProductName { get; set; }
}
