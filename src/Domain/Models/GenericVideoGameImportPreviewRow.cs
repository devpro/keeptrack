using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from a generic video game transaction-history CSV (store purchase history - PSN
/// today, any store exporting the same shape later), for the user to review before commit. See
/// <see cref="Services.GenericVideoGameImportService"/>.
/// </summary>
public class GenericVideoGameImportPreviewRow
{
    /// <summary>The transaction id - unique per line item in every export seen so far.</summary>
    public required string RowId { get; set; }

    /// <summary>The game title, cleaned of a trailing platform suffix (e.g. "(PS4)") when present.</summary>
    public required string Title { get; set; }

    public required string Platform { get; set; }

    /// <summary>The store's own specific product/edition text (e.g. "Grand Theft Auto V : Édition Premium").</summary>
    public string? ProductName { get; set; }

    public required string Vendor { get; set; }

    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? TransactionDate { get; set; }

    public decimal? Price { get; set; }

    public bool AlreadyImported { get; set; }
}
