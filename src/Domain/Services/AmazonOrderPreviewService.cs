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
/// Parses an Amazon.fr order-history export (<b>Request My Data &gt; Your Orders</b>) into review rows.
/// Pure: bytes in, rows out, with no repository access, the caller computing <c>alreadyImportedReferences</c> so this tests without a database.
/// The export has no category column, so this never decides whether an item is a book.
/// <see cref="AmazonOrderPreviewRow.LooksLikeBook"/> only suggests it for the review UI's default filter, since a book's ASIN is usually its ISBN-10, and the user decides.
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
                // Some product names carry a numeric HTML entity instead of the character ("Le Dernier V&#x153;u" for "Le Dernier Vœu").
                // Decoded after the mojibake repair, so the two independent fixes never interact.
                Title = WebUtility.HtmlDecode(FixMojibake(record.ProductName)),
                Asin = record.Asin,
                OrderId = record.OrderId,
                OrderDate = ParseOrderDate(record.OrderDate),
                Price = ParsePrice(record.TotalAmount),
                Vendor = record.Website ?? string.Empty,
                Condition = record.ProductCondition,
                LooksLikeBook = suggestedIsbn is not null,
                SuggestedIsbn = suggestedIsbn,
                // per (order, ASIN), since checking the order alone would flag every item of an order once one was imported (see AmazonImportMergeService.FormatOrderReference)
                AlreadyImported = alreadyImportedReferences.Contains(AmazonImportMergeService.FormatOrderReference(record.OrderId, record.Asin))
            };
        }).ToList();
    }

    /// <summary>
    /// Amazon's export garbles accented text: UTF-8 bytes were re-encoded as Latin-1, so "protection d'écrans" reads "protection d'Ã©crans".
    /// Reading the characters back as Latin-1 bytes and decoding them as UTF-8 repairs it.
    /// The repair is kept only when it contains no U+FFFD replacement character, so text that was already correct is never garbled a second time.
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
        return repaired.Contains('\uFFFD') ? text : repaired;
    }

    /// <summary>
    /// Strips the leading apostrophe Amazon adds against formula injection (the literal <c>'-5'</c> in "Total Discounts") before parsing.
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
    /// ISBN-10 checksum: 10 digits, the last possibly 'X' for 10, whose sum weighted 10 down to 1 is divisible by 11.
    /// A book's ASIN is usually its ISBN-10, so this is a strong sign of a book, unlike a bare length check.
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
