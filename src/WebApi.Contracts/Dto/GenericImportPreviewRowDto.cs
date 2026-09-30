using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One line item parsed from an uploaded generic store/CSV import, awaiting the user's review before anything
/// is imported. Everything the Amazon importer hardcodes (vendor, the media type) is instead read from
/// canonical columns here. See <see cref="GenericImportCommitItemDto"/> for what gets sent back once selected.
/// </summary>
public class GenericImportPreviewRowDto
{
    /// <summary>Correlates a selected/edited row back to this one at commit time. Stable within one file, never stored.</summary>
    public required string RowId { get; set; }

    /// <summary>The item title (from the "Title"/"Product Name" column).</summary>
    public required string Title { get; set; }

    /// <summary>
    /// The media type read from the optional "Type" column, or null when that column is blank/absent or holds
    /// an unrecognized value - the review UI then forces an explicit per-row pick before commit.
    /// </summary>
    public ImportMediaType? SuggestedMediaType { get; set; }

    /// <summary>The order/invoice number, if present - part of the dedup reference.</summary>
    public string? OrderId { get; set; }

    /// <summary>The store's own stable per-product id (ASIN, SKU...) - dedup disambiguator, falls back to the title.</summary>
    public string? ProductId { get; set; }

    public DateOnly? OrderDate { get; set; }

    public decimal? Price { get; set; }

    /// <summary>The store name, read per row - populates the owned copy's Vendor field.</summary>
    public string? Vendor { get; set; }

    /// <summary>The "Website" column - a free-text per-item label (product/order URL, seller...) that goes into
    /// the owned copy's Reference, independent of Vendor.</summary>
    public string? Website { get; set; }

    /// <summary>Book author, if an "Author" column is present.</summary>
    public string? Author { get; set; }

    /// <summary>Video game platform, if a "Platform" column is present.</summary>
    public string? Platform { get; set; }

    public int? Year { get; set; }

    /// <summary>Item condition ("New", "Used"...) - preserved on the created copy's Product field.</summary>
    public string? Condition { get; set; }

    /// <summary>Book ISBN, if an "ISBN" column is present.</summary>
    public string? Isbn { get; set; }

    /// <summary>Physical (default) or Digital, from a "Copy"/"Format" column.</summary>
    public CopyType CopyType { get; set; }

    /// <summary>
    /// True when an existing item already has an owned copy referencing this order line. Defaults to
    /// unchecked/hidden in the review UI, but stays selectable in case the user wants to re-import anyway.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
