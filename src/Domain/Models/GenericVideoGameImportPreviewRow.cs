using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One line item parsed from a video game transaction CSV, such as PSN's purchase history or any store exporting the same shape, for the user to review before commit.
/// See <see cref="Services.GenericVideoGameImportService"/>.
/// </summary>
public class GenericVideoGameImportPreviewRow
{
    /// <summary>The transaction id, unique per line item in every known export.</summary>
    public required string RowId { get; set; }

    /// <summary>The game title, without a trailing platform suffix such as "(PS4)".</summary>
    public required string Title { get; set; }

    public required string Platform { get; set; }

    /// <summary>The store's product or edition text, such as "Grand Theft Auto V : Édition Premium".</summary>
    public string? ProductName { get; set; }

    public required string Vendor { get; set; }

    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public DateOnly? TransactionDate { get; set; }

    public decimal? Price { get; set; }

    public bool AlreadyImported { get; set; }
}
