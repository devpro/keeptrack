using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from a generic store/CSV import (any retailer export the user has reshaped into the
/// canonical column set in a spreadsheet), before the user has reviewed/selected it. Transient - never
/// persisted. Produced by <see cref="Services.GenericImportService"/> and mapped to
/// <c>GenericImportPreviewRowDto</c> for the review UI.
/// Unlike <see cref="AmazonOrderPreviewRow"/>, everything Amazon hardcodes (vendor, the "is this a book"
/// heuristic) is instead read straight from columns here: <see cref="SuggestedMediaType"/> comes from a
/// "Type" column, <see cref="Vendor"/> from a per-row column, etc.
/// </summary>
public class GenericImportPreviewRow
{
    /// <summary>
    /// Stable within one file, used only to correlate a selected/edited row back to this one at commit time.
    /// Never stored. Built from order id + product id + title so a single order's several line items stay distinct.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>The item title (from the "Title"/"Product Name" column).</summary>
    public required string Title { get; set; }

    /// <summary>
    /// The media type read from the optional "Type" column, or null when that column is blank/absent or holds
    /// an unrecognized value - in which case the review UI forces an explicit per-row pick before commit.
    /// </summary>
    public ImportMediaType? SuggestedMediaType { get; set; }

    /// <summary>The order/invoice number, if the file has one - part of the dedup reference.</summary>
    public string? OrderId { get; set; }

    /// <summary>
    /// The store's own stable per-product id (an Amazon ASIN, a retailer SKU...) - the disambiguator that
    /// keeps two different line items sharing one order distinct in the dedup reference. Falls back to the
    /// title when absent.
    /// </summary>
    public string? ProductId { get; set; }

    public DateOnly? OrderDate { get; set; }

    /// <summary>What was paid for this item, if a price/amount column is present.</summary>
    public decimal? Price { get; set; }

    /// <summary>The store name, read per row (never hardcoded) - populates the owned copy's Vendor field.</summary>
    public string? Vendor { get; set; }

    /// <summary>
    /// The "Website" column - a free-text per-item label (product/order URL, seller...) that goes into the owned
    /// copy's Reference (see <see cref="Services.GenericImportService.FormatReference"/>), independent of Vendor.
    /// </summary>
    public string? Website { get; set; }

    /// <summary>Book author, if an "Author" column is present - pre-fills the created book.</summary>
    public string? Author { get; set; }

    /// <summary>Video game platform, if a "Platform" column is present - pre-fills the created game's copy.</summary>
    public string? Platform { get; set; }

    /// <summary>Release/publication year, if a "Year" column is present.</summary>
    public int? Year { get; set; }

    /// <summary>
    /// Item condition ("New", "Used"...) from a "Condition"/"Product Condition" column - preserved on the
    /// created owned copy's Product field rather than discarded (the one behavioral difference from the Amazon
    /// importer, which treats condition as display-only).
    /// </summary>
    public string? Condition { get; set; }

    /// <summary>Book ISBN, if an "ISBN" column is present.</summary>
    public string? Isbn { get; set; }

    /// <summary>Whether the row's "Copy"/"Format" column indicated a digital (vs. the default physical) copy.</summary>
    public CopyType CopyType { get; set; }

    /// <summary>
    /// True when an existing item already has an owned copy referencing this order line - see
    /// <see cref="Services.GenericImportService.FormatReference"/>. Defaults to unchecked in the review UI,
    /// but stays selectable in case the user wants to re-import anyway.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
