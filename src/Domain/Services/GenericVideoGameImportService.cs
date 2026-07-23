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
/// Parses a generic video game transaction-history CSV (a store's purchase history export - PSN's own GDPR
/// export today, reshaped by the user into this shape; any store exporting the same columns would work too,
/// since <see cref="Vendor"/> is a per-row column rather than something hardcoded here) into review rows.
/// Pure: bytes in, rows out, no repository access - <c>alreadyImportedReferences</c> below is computed by
/// the caller from already-fetched data so this stays testable without a database. Every row is a video
/// game (unlike the Amazon import, which mixes several media types and needs a per-row type guess) - the
/// export is store-purchase history for games specifically.
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
            // Transaction Id alone isn't unique per row (see FormatReference's doc comment - a bundled
            // transaction has several lines sharing one), so RowId needs the same product disambiguator,
            // same shape as AmazonOrderPreviewRow.RowId's "{OrderId}:{Asin}".
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
    /// Strips a trailing " ({platform})" suffix from the game title (e.g. "Grand Theft Auto V (PS4)" with
    /// platform "PS4" becomes "Grand Theft Auto V") - the export's own title column routinely repeats the
    /// platform, redundant now that <see cref="GenericVideoGameImportPreviewRow.Platform"/> is its own
    /// column. Falls back to the raw title unchanged when the suffix isn't present, so a source that doesn't
    /// follow this convention is left alone rather than mangled.
    /// </summary>
    public static string CleanTitle(string gameName, string platform)
    {
        var suffix = $" ({platform})";
        return gameName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ? gameName[..^suffix.Length] : gameName;
    }

    /// <summary>
    /// The one place that formats an owned copy's <c>Reference</c> for an imported transaction line -
    /// human-readable, and also the exact-match dedup key
    /// <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/> looks for on a later
    /// re-import. No vendor name here - <see cref="VideoGamePlatformModel.Vendor"/> already carries that.
    ///
    /// Appends <paramref name="productName"/> (falling back to <paramref name="fallbackTitle"/> when blank)
    /// because the transaction id + order id pair is *not* reliably unique per line: a single transaction
    /// commonly bundles several different products together (confirmed against a real PSN export - one
    /// order/transaction contained three separate "Far Cry 4" DLC packs, each its own line with a distinct
    /// Product Name but the exact same Transaction Id/Order Id). Without this, two of those three lines'
    /// references collided and were wrongly treated as re-imports of each other - the same class of bug
    /// <see cref="AmazonImportMergeService.FormatOrderReference"/> already avoids by including the ASIN
    /// alongside the order id, since Amazon's export has a real stable per-product id to use for that;
    /// this export has no such id, so the product/edition text is the next best disambiguator.
    /// </summary>
    public static string FormatReference(string transactionId, string orderId, string? productName, string fallbackTitle)
    {
        var descriptor = string.IsNullOrWhiteSpace(productName) ? fallbackTitle : productName;
        return $"Order {orderId} (transaction {transactionId}) - {descriptor}";
    }

    /// <summary>
    /// Reference-data linking is expected to overwrite the created item's title with the provider's
    /// canonical value, and the user may have already cleaned up the title before commit - so this is the
    /// one place the source export's original listing text is preserved, for an item created by this
    /// import. Only used at creation time: a pre-existing item's provenance isn't this import's to invent.
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
