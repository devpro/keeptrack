using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One line item parsed from an uploaded Amazon order-history export, awaiting the user's review before
/// anything is imported. See <see cref="AmazonImportCommitItemDto"/> for what gets sent back once selected.
/// </summary>
public class AmazonOrderPreviewRowDto
{
    /// <summary>
    /// Correlates a selected/edited row back to this one at commit time. Stable within one export, never stored.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>
    /// Amazon's product name, with the export's mojibake repaired.
    /// </summary>
    public required string Title { get; set; }

    /// <summary>
    /// Amazon's own product identifier for this order line.
    /// </summary>
    public required string Asin { get; set; }

    /// <summary>
    /// Amazon's order number.
    /// </summary>
    public required string OrderId { get; set; }

    public DateOnly? OrderDate { get; set; }

    /// <summary>
    /// What was actually paid for this item - tax and any per-item discount already netted in.
    /// </summary>
    public decimal? Price { get; set; }

    /// <summary>
    /// The storefront the order was placed on (e.g. "Amazon.fr").
    /// </summary>
    public required string Vendor { get; set; }

    /// <summary>
    /// Display only ("New", "Used"...) - not carried onto the created book.
    /// </summary>
    public string? Condition { get; set; }

    /// <summary>
    /// True when <see cref="Asin"/> passes an ISBN-10 checksum - the review table's default filter.
    /// </summary>
    public bool LooksLikeBook { get; set; }

    /// <summary>
    /// <see cref="Asin"/> again, only when <see cref="LooksLikeBook"/> is true.
    /// </summary>
    public string? SuggestedIsbn { get; set; }

    /// <summary>
    /// True when an existing book already has an owned version referencing this order. Defaults to
    /// unchecked in the review UI, but stays editable/selectable in case the user wants to re-import anyway.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
