using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from a generic CSV import, any store export reshaped into the canonical columns, before the user reviews and selects it.
/// Never persisted.
/// Produced by <see cref="Services.GenericImportService"/> and mapped to <c>GenericImportPreviewRowDto</c> for the review UI.
/// What the Amazon import hardcodes (the vendor, the "is this a book" heuristic) is read from columns here,
/// such as <see cref="SuggestedMediaType"/> from "Type" and <see cref="Vendor"/> per row.
/// </summary>
public class GenericImportPreviewRow
{
    /// <summary>
    /// Stable within one file, used only to match a selected or edited row back to this one at commit time.
    /// Built from the order id, product id and title, so several line items of one order stay distinct.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>The item title, from the "Title" or "Product Name" column.</summary>
    public required string Title { get; set; }

    /// <summary>
    /// The media type read from the optional "Type" column.
    /// Null when the column is blank, absent or unrecognized, and the review UI then requires a pick for the row before commit.
    /// </summary>
    public ImportMediaType? SuggestedMediaType { get; set; }

    /// <summary>The order or invoice number, if the file has one, part of the dedup reference.</summary>
    public string? OrderId { get; set; }

    /// <summary>
    /// The store's stable product id (an Amazon ASIN, a retailer SKU), which keeps two line items of one order distinct in the dedup reference.
    /// The title stands in when it is absent.
    /// </summary>
    public string? ProductId { get; set; }

    public DateOnly? OrderDate { get; set; }

    /// <summary>What was paid for this item, if a price or amount column is present.</summary>
    public decimal? Price { get; set; }

    /// <summary>The store name, read per row, which becomes the owned copy's Vendor.</summary>
    public string? Vendor { get; set; }

    /// <summary>
    /// The "Website" column, a free-text label per item (product or order URL, seller) that becomes the owned copy's Reference,
    /// independent of Vendor (see <see cref="Services.GenericImportService.FormatReference"/>).
    /// </summary>
    public string? Website { get; set; }

    /// <summary>Book author, if an "Author" column is present, which fills the created book.</summary>
    public string? Author { get; set; }

    /// <summary>Video game platform, if a "Platform" column is present, which fills the created game's copy.</summary>
    public string? Platform { get; set; }

    /// <summary>Release or publication year, if a "Year" column is present.</summary>
    public int? Year { get; set; }

    /// <summary>
    /// Item condition ("New", "Used") from a "Condition" or "Product Condition" column.
    /// It is kept on the created copy's product name (owner's request), where the Amazon import only displays it.
    /// </summary>
    public string? Condition { get; set; }

    /// <summary>Book ISBN, if an "ISBN" column is present.</summary>
    public string? Isbn { get; set; }

    /// <summary>Whether the row's "Copy" or "Format" column indicated a digital copy rather than the default physical one.</summary>
    public CopyType CopyType { get; set; }

    /// <summary>
    /// True when an existing item already has an owned copy referencing this order line (see <see cref="Services.GenericImportService.FormatReference"/>).
    /// The review UI leaves it unchecked but selectable, so the user can still import it again.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
