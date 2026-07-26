using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One line item parsed from an uploaded generic video game transaction-history export, awaiting the user's
/// review before anything is imported. See <see cref="GenericVideoGameImportCommitItemDto"/> for what gets
/// sent back once selected.
/// </summary>
public class GenericVideoGameImportPreviewRowDto
{
    /// <summary>
    /// Correlates a selected/edited row back to this one at commit time. Stable within one export, never stored.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>
    /// The game title, cleaned of a trailing platform suffix (e.g. "(PS4)") when present.
    /// </summary>
    public required string Title { get; set; }

    public required string Platform { get; set; }

    /// <summary>
    /// The store's own specific product/edition text (e.g. "Grand Theft Auto V : Édition Premium").
    /// </summary>
    public string? ProductName { get; set; }

    /// <summary>
    /// The storefront the transaction was made on (e.g. "PlayStation Store").
    /// </summary>
    public required string Vendor { get; set; }

    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? TransactionDate { get; set; }

    public decimal? Price { get; set; }

    /// <summary>
    /// True when an existing video game already has a platform entry referencing this transaction. Defaults
    /// to unchecked/hidden in the review UI, but stays editable/selectable in case the user wants to
    /// re-import anyway.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
