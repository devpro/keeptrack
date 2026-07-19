using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using CsvHelper;
using CsvHelper.Configuration;
using CsvHelper.Configuration.Attributes;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Parses an Amazon.fr order-history export ("Request My Data" -> "Your Orders") into review rows. Pure:
/// bytes in, rows out, no repository access - <c>alreadyImportedReferences</c> below is computed by the
/// caller from already-fetched data so this stays testable without a database.
/// Amazon's export has no category column at all, so this never decides "is this a book" on its own - it
/// only computes <see cref="AmazonOrderPreviewRow.LooksLikeBook"/> as a checksum-verified suggestion for
/// the review UI's default filter, confirmed against a real export (an Amazon book's ASIN is routinely its
/// ISBN-10). The user makes the actual call.
/// </summary>
public static class AmazonOrderPreviewService
{
    private sealed class AmazonOrderRecord
    {
        [Name("ASIN")]
        public required string Asin { get; set; }

        [Name("Order Date")]
        public required string OrderDate { get; set; }

        [Name("Order ID")]
        public required string OrderId { get; set; }

        [Name("Product Name")]
        public required string ProductName { get; set; }

        [Name("Product Condition")]
        public string? ProductCondition { get; set; }

        [Name("Total Amount")]
        public string? TotalAmount { get; set; }

        [Name("Website")]
        public string? Website { get; set; }
    }

    private static readonly CsvConfiguration s_csvConfiguration = new(CultureInfo.InvariantCulture)
    {
        PrepareHeaderForMatch = args => args.Header.Trim().ToLowerInvariant()
    };

    public static List<AmazonOrderPreviewRow> BuildPreview(Stream csvStream, IReadOnlySet<string> alreadyImportedReferences)
    {
        using var reader = new StreamReader(csvStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        using var csv = new CsvReader(reader, s_csvConfiguration);
        var records = csv.GetRecords<AmazonOrderRecord>().ToList();

        return records.Select(record =>
        {
            var suggestedIsbn = IsValidIsbn10(record.Asin) ? record.Asin : null;

            return new AmazonOrderPreviewRow
            {
                RowId = $"{record.OrderId}:{record.Asin}",
                // Some product names also carry a raw numeric HTML entity instead of the character itself
                // (confirmed in a real export: "Le Dernier V&#x153;u" instead of "Le Dernier Vœu"). Decoded
                // after the mojibake repair, not before - the entity text is plain ASCII, so it round-trips
                // through that repair unchanged regardless of order, but repairing first keeps the two
                // independent fixes from interacting in either direction.
                Title = WebUtility.HtmlDecode(FixMojibake(record.ProductName)),
                Asin = record.Asin,
                OrderId = record.OrderId,
                OrderDate = ParseOrderDate(record.OrderDate),
                Price = ParsePrice(record.TotalAmount),
                Vendor = record.Website ?? string.Empty,
                Condition = record.ProductCondition,
                LooksLikeBook = suggestedIsbn is not null,
                SuggestedIsbn = suggestedIsbn,
                // Per (order, ASIN), not per order - an order commonly has several different line items, and
                // an order-id-only check would incorrectly flag every sibling item once any one of them had
                // actually been imported (see AmazonImportMergeService.FormatOrderReference).
                AlreadyImported = alreadyImportedReferences.Contains(AmazonImportMergeService.FormatOrderReference(record.OrderId, record.Asin))
            };
        }).ToList();
    }

    /// <summary>
    /// Amazon's export is mojibake for accented text: UTF-8 bytes were re-encoded as if they were Latin-1
    /// (confirmed against the raw bytes of a real export - "protection d'écrans" reads back as "protection
    /// d'Ã©crans"). Reinterpreting the decoded chars as Latin-1 bytes and re-decoding as UTF-8 repairs it.
    /// The repaired text is only used when it contains no U+FFFD replacement character, so already-correct
    /// text (a lone, validly-encoded accented char has no valid single-byte UTF-8 reading) round-trips
    /// untouched instead of being corrupted a second time.
    /// </summary>
    private static string FixMojibake(string text)
    {
        if (text.Length == 0 || text.Any(c => c > 255)) return text;

        var bytes = new byte[text.Length];
        for (var i = 0; i < text.Length; i++)
        {
            bytes[i] = (byte)text[i];
        }

        var repaired = Encoding.UTF8.GetString(bytes);
        return repaired.Contains('�') ? text : repaired;
    }

    /// <summary>
    /// Strips Amazon's Excel-formula-injection-prevention leading apostrophe (confirmed in a real export's
    /// "Total Discounts" column, e.g. the literal text <c>'-5'</c>) before parsing.
    /// </summary>
    private static decimal? ParsePrice(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var cleaned = raw.Trim().Trim('\'');
        return decimal.TryParse(cleaned, NumberStyles.Number, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    private static DateOnly? ParseOrderDate(string raw) =>
        DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? DateOnly.FromDateTime(parsed.UtcDateTime)
            : null;

    /// <summary>
    /// ISBN-10 checksum: 10 digits (last one may be 'X'/'x' meaning check value 10), weighted sum over
    /// position (10 down to 1) divisible by 11. Amazon's book ASINs are routinely a real ISBN-10, so this
    /// is a strong, false-positive-resistant "is this a book" signal - unlike a bare "10 characters" check.
    /// </summary>
    private static bool IsValidIsbn10(string asin)
    {
        if (asin.Length != 10) return false;

        var sum = 0;
        for (var i = 0; i < 9; i++)
        {
            if (!char.IsDigit(asin[i])) return false;
            sum += (asin[i] - '0') * (10 - i);
        }

        var last = asin[9];
        int checkDigit;
        if (last is 'X' or 'x') checkDigit = 10;
        else if (char.IsDigit(last)) checkDigit = last - '0';
        else return false;

        sum += checkDigit;
        return sum % 11 == 0;
    }
}
