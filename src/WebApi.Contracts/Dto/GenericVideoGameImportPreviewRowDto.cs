using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One line item parsed from an uploaded video game transaction export, awaiting the user's review before anything is imported.
/// See <see cref="GenericVideoGameImportCommitItemDto"/> for what gets sent back once selected.
/// </summary>
public class GenericVideoGameImportPreviewRowDto
{
    /// <summary>
    /// Matches a selected or edited row back to this one at commit time, stable within one export and never stored.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>
    /// The game title, without a trailing platform suffix such as "(PS4)".
    /// </summary>
    public required string Title { get; set; }

    public required string Platform { get; set; }

    /// <summary>
    /// The store's product or edition text, such as "Grand Theft Auto V : Édition Premium".
    /// </summary>
    public string? ProductName { get; set; }

    /// <summary>
    /// The storefront of the transaction, such as "PlayStation Store".
    /// </summary>
    public required string Vendor { get; set; }

    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? TransactionDate { get; set; }

    public decimal? Price { get; set; }

    /// <summary>
    /// True when an existing video game already has a platform entry referencing this transaction.
    /// The review UI leaves it unchecked but selectable, so the user can still import it again.
    /// </summary>
    public bool AlreadyImported { get; set; }
}
