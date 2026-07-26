using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from an Amazon order-history export, before the user has reviewed/selected it.
/// Transient - never persisted. Produced by <see cref="Services.AmazonOrderPreviewService"/> and mapped
/// to <c>AmazonOrderPreviewRowDto</c> by <c>AmazonOrderPreviewRowDtoMapper</c> for the review UI.
/// </summary>
public class AmazonOrderPreviewRow
{
    /// <summary>
    /// <c>"{OrderId}:{Asin}"</c> - stable within one export, used only to correlate a selected/edited row
    /// back to this one at commit time. Never stored.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>Amazon's product name, with the export's mojibake repaired.</summary>
    public required string Title { get; set; }

    public required string Asin { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? OrderDate { get; set; }

    /// <summary>What was actually paid for this item - tax and any per-item discount already netted in.</summary>
    public decimal? Price { get; set; }

    public required string Vendor { get; set; }

    /// <summary>Display only ("New", "Used"...) - not carried onto the created book.</summary>
    public string? Condition { get; set; }

    /// <summary>True when <see cref="Asin"/> passes an ISBN-10 checksum - the review table's default filter.</summary>
    public bool LooksLikeBook { get; set; }

    /// <summary><see cref="Asin"/> again, only when <see cref="LooksLikeBook"/> is true.</summary>
    public string? SuggestedIsbn { get; set; }

    /// <summary>
    /// True when an existing book already has an owned version referencing this order - see
    /// <see cref="Services.AmazonBookImportMergeService.FormatOrderReference"/>.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
