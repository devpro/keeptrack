using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from an Amazon order-history export, before the user reviews and selects it.
/// Never persisted.
/// Produced by <see cref="Services.AmazonOrderPreviewService"/> and mapped to <c>AmazonOrderPreviewRowDto</c> for the review UI.
/// </summary>
public class AmazonOrderPreviewRow
{
    /// <summary>
    /// <c>"{OrderId}:{Asin}"</c>, stable within one export, used only to match a selected or edited row back to this one at commit time.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>Amazon's product name, with the export's mojibake repaired.</summary>
    public required string Title { get; set; }

    public required string Asin { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? OrderDate { get; set; }

    /// <summary>What was actually paid for this item, tax and any per-item discount included.</summary>
    public decimal? Price { get; set; }

    public required string Vendor { get; set; }

    /// <summary>Display only ("New", "Used"), not carried onto the created book.</summary>
    public string? Condition { get; set; }

    /// <summary>True when <see cref="Asin"/> passes an ISBN-10 checksum, the review table's default filter.</summary>
    public bool LooksLikeBook { get; set; }

    /// <summary><see cref="Asin"/> again, only when <see cref="LooksLikeBook"/> is true.</summary>
    public string? SuggestedIsbn { get; set; }

    /// <summary>
    /// True when an existing book already has an owned version referencing this order (see <see cref="Services.AmazonImportMergeService.FormatOrderReference"/>).
    /// </summary>
    public bool AlreadyImported { get; set; }
}
