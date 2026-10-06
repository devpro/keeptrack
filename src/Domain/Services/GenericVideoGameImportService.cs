using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using CsvHelper;
using CsvHelper.Configuration;
using CsvHelper.Configuration.Attributes;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Parses a video game transaction CSV, such as PSN's GDPR export, into review rows.
/// Any store exporting the same columns works, since the vendor is a column rather than hardcoded.
/// Pure: bytes in, rows out, with no repository access, the caller computing <c>alreadyImportedReferences</c> so this tests without a database.
/// Every row is a video game, unlike the Amazon import, which mixes media types.
/// </summary>
public static class GenericVideoGameImportService
{
    private sealed class VideoGameTransactionRecord
    {
        [Name("Transaction Date")]
        public required string TransactionDate { get; set; }

        [Name("Game Name")]
        public required string GameName { get; set; }

        [Name("Product Name")]
        public string? ProductName { get; set; }

        [Name("Platform")]
        public required string Platform { get; set; }

        [Name("Vendor")]
        public required string Vendor { get; set; }

        [Name("Transaction Id")]
        public required string TransactionId { get; set; }

        [Name("Order Id")]
        public required string OrderId { get; set; }

        [Name("Final Price (€)")]
        public string? FinalPrice { get; set; }
    }

    private static readonly CsvConfiguration s_csvConfiguration = new(CultureInfo.InvariantCulture)
    {
        PrepareHeaderForMatch = args => args.Header.Trim().ToLowerInvariant()
    };

    public static List<GenericVideoGameImportPreviewRow> BuildPreview(Stream csvStream, IReadOnlySet<string> alreadyImportedReferences)
    {
        using var reader = new StreamReader(csvStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        using var csv = new CsvReader(reader, s_csvConfiguration);
        var records = csv.GetRecords<VideoGameTransactionRecord>().ToList();

        return records.Select(record => new GenericVideoGameImportPreviewRow
        {
            // a bundled transaction has several lines sharing one transaction id (see FormatReference), so the row id adds the product, like AmazonOrderPreviewRow.RowId's "{OrderId}:{Asin}"
            RowId = $"{record.TransactionId}:{record.ProductName ?? record.GameName}",
            Title = CleanTitle(record.GameName, record.Platform),
            Platform = record.Platform,
            ProductName = record.ProductName,
            Vendor = record.Vendor,
            TransactionId = record.TransactionId,
            OrderId = record.OrderId,
            TransactionDate = ParseTransactionDate(record.TransactionDate),
            Price = ParsePrice(record.FinalPrice),
            AlreadyImported = alreadyImportedReferences.Contains(FormatReference(record.TransactionId, record.OrderId, record.ProductName, record.GameName))
        }).ToList();
    }

    /// <summary>
    /// Strips a trailing " ({platform})" from the title, so "Grand Theft Auto V (PS4)" on "PS4" becomes "Grand Theft Auto V", since the platform has its own column.
    /// A title without the suffix is returned unchanged.
    /// </summary>
    public static string CleanTitle(string gameName, string platform)
    {
        var suffix = $" ({platform})";
        return gameName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ? gameName[..^suffix.Length] : gameName;
    }

    /// <summary>
    /// Formats an imported transaction line's owned copy <c>Reference</c>, which is human-readable and also the exact dedup key <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/> looks for on a re-import.
    /// It carries no vendor, which <see cref="VideoGamePlatformModel.Vendor"/> holds.
    ///
    /// It appends <paramref name="productName"/>, or <paramref name="fallbackTitle"/> when blank, since the transaction and order ids are not unique per line.
    /// One PSN transaction bundled three "Far Cry 4" DLC packs, each a line with its own product name but the same ids, and without it they would be skipped as re-imports of each other.
    /// This export has no product id like Amazon's ASIN, so the product text is the best disambiguator.
    /// </summary>
    public static string FormatReference(string transactionId, string orderId, string? productName, string fallbackTitle)
    {
        var descriptor = string.IsNullOrWhiteSpace(productName) ? fallbackTitle : productName;
        return $"Order {orderId} (transaction {transactionId}) - {descriptor}";
    }

    /// <summary>
    /// Keeps the export's original listing text on an item this import creates.
    /// Reference linking may overwrite the title, and the user may have edited it before commit.
    /// Only used on creation, since an existing item's provenance is not this import's to invent.
    /// </summary>
    public static string BuildProvenanceNotes(string vendor, string sourceTitle) => $"Title from {vendor}: {sourceTitle}";

    private static decimal? ParsePrice(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        return decimal.TryParse(raw.Trim(), NumberStyles.Number, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    private static DateOnly? ParseTransactionDate(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? DateOnly.FromDateTime(parsed.UtcDateTime)
            : null;
}
