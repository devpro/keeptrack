using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One line item parsed from an uploaded generic CSV import, awaiting the user's review before anything is imported.
/// What the Amazon import hardcodes (the vendor, the media type) is read from canonical columns here.
/// See <see cref="GenericImportCommitItemDto"/> for what gets sent back once selected.
/// </summary>
public class GenericImportPreviewRowDto
{
    /// <summary>Matches a selected or edited row back to this one at commit time, stable within one file and never stored.</summary>
    public required string RowId { get; set; }

    /// <summary>The item title, from the "Title" or "Product Name" column.</summary>
    public required string Title { get; set; }

    /// <summary>
    /// The media type from the optional "Type" column, or null when it is blank, absent or unrecognized, and the review UI then requires a pick for the row.
    /// </summary>
    public ImportMediaType? SuggestedMediaType { get; set; }

    /// <summary>The order or invoice number, if present, part of the dedup reference.</summary>
    public string? OrderId { get; set; }

    /// <summary>The store's stable product id (ASIN, SKU), which disambiguates the dedup reference, the title standing in when absent.</summary>
    public string? ProductId { get; set; }

    public DateOnly? OrderDate { get; set; }

    public decimal? Price { get; set; }

    /// <summary>The store name, read per row, which becomes the owned copy's Vendor.</summary>
    public string? Vendor { get; set; }

    /// <summary>The "Website" column, a free-text label (product or order URL, seller) that becomes the owned copy's Reference, independent of the Vendor.</summary>
    public string? Website { get; set; }

    /// <summary>Book author, if an "Author" column is present.</summary>
    public string? Author { get; set; }

    /// <summary>Video game platform, if a "Platform" column is present.</summary>
    public string? Platform { get; set; }

    public int? Year { get; set; }

    /// <summary>Item condition ("New", "Used"), kept on the created copy's product name.</summary>
    public string? Condition { get; set; }

    /// <summary>Book ISBN, if an "ISBN" column is present.</summary>
    public string? Isbn { get; set; }

    /// <summary>Physical (the default) or Digital, from a "Copy" or "Format" column.</summary>
    public CopyType CopyType { get; set; }

    /// <summary>
    /// True when an existing item already has an owned copy referencing this order line.
    /// The review UI leaves it unchecked but selectable, so the user can still import it again.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
