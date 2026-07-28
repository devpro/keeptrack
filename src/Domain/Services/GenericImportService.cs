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
/// Parses a generic store/CSV import into review rows. Pure: bytes in, rows out, no repository access -
/// <c>alreadyImportedReferences</c> below is computed by the caller from already-fetched data so this stays
/// testable without a database.
///
/// This is the store-agnostic generalization of <see cref="AmazonOrderPreviewService"/>: instead of hardcoding
/// Amazon's vendor, columns, and its ISBN-based "is this a book" guess, every field is read from a canonical,
/// case-insensitive column set (all optional except the title) the user reshapes their own export into within a
/// spreadsheet. Notably a "Type" column, when present, decides each row's media type directly - no per-row
/// guessing - which is the whole reason the Amazon page's per-row picker can be pre-filled here.
/// </summary>
public static class GenericImportService
{
    private sealed class GenericImportRecord
    {
        // Title is the one required column. Its aliases cover the common retailer header ("Product Name").
        [Name("Title", "Product Name")]
        public required string Title { get; set; }

        [Optional]
        [Name("Type")]
        public string? Type { get; set; }

        [Optional]
        [Name("Order Date", "Date")]
        public string? OrderDate { get; set; }

        [Optional]
        [Name("Order ID", "Order Id")]
        public string? OrderId { get; set; }

        [Optional]
        [Name("Product Id", "Product ID", "ASIN", "SKU")]
        public string? ProductId { get; set; }

        [Optional]
        [Name("Price", "Total Amount", "Amount")]
        public string? Price { get; set; }

        // The store name - populates the owned copy's Vendor field only. Its own column, separate from Website
        // below (which feeds the copy's Reference, not the Vendor field).
        [Optional]
        [Name("Vendor", "Store")]
        public string? Vendor { get; set; }

        // Free-text label that goes into the owned copy's Reference (a product/order URL, seller...). Feeds the
        // Reference only, never the Vendor field.
        [Optional]
        [Name("Website")]
        public string? Website { get; set; }

        [Optional]
        [Name("Author")]
        public string? Author { get; set; }

        [Optional]
        [Name("Platform")]
        public string? Platform { get; set; }

        [Optional]
        [Name("Year")]
        public string? Year { get; set; }

        [Optional]
        [Name("Condition", "Product Condition")]
        public string? Condition { get; set; }

        [Optional]
        [Name("ISBN")]
        public string? Isbn { get; set; }

        [Optional]
        [Name("Copy", "Format")]
        public string? Copy { get; set; }
    }

    private static readonly CsvConfiguration s_csvConfiguration = new(CultureInfo.InvariantCulture)
    {
        PrepareHeaderForMatch = args => args.Header.Trim().ToLowerInvariant()
    };

    public static List<GenericImportPreviewRow> BuildPreview(Stream csvStream, IReadOnlySet<string> alreadyImportedReferences)
    {
        using var reader = new StreamReader(csvStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        using var csv = new CsvReader(reader, s_csvConfiguration);
        var records = csv.GetRecords<GenericImportRecord>().ToList();

        return records.Select(record =>
        {
            var title = record.Title.Trim();
            var orderId = Trimmed(record.OrderId);
            var productId = Trimmed(record.ProductId);
            var vendor = Trimmed(record.Vendor);
            var website = Trimmed(record.Website);

            return new GenericImportPreviewRow
            {
                RowId = $"{orderId}:{productId}:{title}",
                Title = title,
                SuggestedMediaType = ParseMediaType(record.Type),
                OrderId = orderId,
                ProductId = productId,
                OrderDate = ParseDate(record.OrderDate),
                Price = ParsePrice(record.Price),
                Vendor = vendor,
                Website = website,
                Author = Trimmed(record.Author),
                Platform = Trimmed(record.Platform),
                Year = ParseYear(record.Year),
                Condition = Trimmed(record.Condition),
                Isbn = Trimmed(record.Isbn),
                CopyType = ParseCopyType(record.Copy),
                AlreadyImported = alreadyImportedReferences.Contains(FormatReference(website, orderId, productId, title))
            };
        }).ToList();
    }

    /// <summary>
    /// The one place that formats an owned copy's <c>Reference</c> for an imported row - human-readable, and
    /// also the exact-match dedup key <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/>
    /// looks for on a later re-import. The leading label is the <paramref name="website"/> value (the free-text
    /// "Website" column - a product/order URL, seller...), NOT the vendor: the reference is deliberately
    /// independent of the Vendor field. Dedup uniqueness comes from the product id (falling back to the title
    /// when the file has none) alongside the order id, not from that label: a single order commonly contains
    /// several different line items, and order-id-only matching would silently skip every sibling once any one
    /// of them had been imported - the same class of bug <see cref="AmazonImportMergeService.FormatOrderReference"/>
    /// avoids with the ASIN and <see cref="GenericVideoGameImportService.FormatReference"/> avoids with the
    /// product name. So a non-unique <paramref name="website"/> label is harmless here.
    /// </summary>
    public static string FormatReference(string? website, string? orderId, string? productId, string title)
    {
        var prefix = string.IsNullOrWhiteSpace(website) ? "Order" : $"{website.Trim()} order";
        var order = string.IsNullOrWhiteSpace(orderId) ? "?" : orderId.Trim();
        var descriptor = string.IsNullOrWhiteSpace(productId) ? title : productId.Trim();
        return $"{prefix} {order} ({descriptor})";
    }

    /// <summary>
    /// Reference-data linking is expected to overwrite the created item's title (and, for a book, its ISBN)
    /// with the provider's canonical values, and the user may have already cleaned up the title before commit
    /// - so this is the one place the source export's original listing text is preserved, for an item created
    /// by this import. Only used at creation time: a pre-existing item's provenance isn't this import's to
    /// invent. <paramref name="isbn"/> is null for every domain but Book.
    /// </summary>
    public static string BuildProvenanceNotes(string? vendor, string sourceTitle, string? isbn)
    {
        var source = string.IsNullOrWhiteSpace(vendor) ? "import" : vendor.Trim();
        var lines = new List<string> { $"Title from {source}: {sourceTitle}" };
        if (!string.IsNullOrWhiteSpace(isbn)) lines.Add($"ISBN from {source}: {isbn.Trim()}");
        return string.Join('\n', lines);
    }

    /// <summary>
    /// Maps a free-text "Type" column value onto <see cref="ImportMediaType"/>, tolerating the natural
    /// spellings a user would type in a spreadsheet ("TV Show", "Video Game", "Film", "Jeu"...). Returns null
    /// for a blank or unrecognized value, which the review UI turns into a required per-row pick rather than
    /// guessing - the same "don't guess when you don't have the info" principle used across the app.
    /// </summary>
    public static ImportMediaType? ParseMediaType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var normalized = new string(raw.Trim().ToLowerInvariant().Where(c => c is not (' ' or '-' or '_')).ToArray());
        return normalized switch
        {
            "book" or "books" or "livre" or "livres" => ImportMediaType.Book,
            "movie" or "movies" or "film" or "films" => ImportMediaType.Movie,
            "tvshow" or "tvshows" or "tv" or "show" or "shows" or "series" or "serie" => ImportMediaType.TvShow,
            "videogame" or "videogames" or "game" or "games" or "jeu" or "jeux" => ImportMediaType.VideoGame,
            "gear" or "equipment" or "equipement" => ImportMediaType.Gear,
            "collectible" or "collectibles" or "collectable" or "collectables" => ImportMediaType.Collectible,
            _ => null
        };
    }

    private static string? Trimmed(string? raw) => string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();

    private static CopyType ParseCopyType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return CopyType.Physical;
        return raw.Trim().ToLowerInvariant() switch
        {
            "digital" or "digitale" or "numérique" or "numerique" or "dematerialise" or "dématérialisé" => CopyType.Digital,
            _ => CopyType.Physical
        };
    }

    /// <summary>
    /// Strips a leading apostrophe (a spreadsheet's Excel-formula-injection guard, e.g. the literal <c>'-5</c>)
    /// before parsing - the same defense <see cref="AmazonOrderPreviewService"/> needs.
    /// </summary>
    private static decimal? ParsePrice(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var cleaned = raw.Trim().Trim('\'').Replace("€", "").Replace("$", "").Replace("£", "").Trim();
        return decimal.TryParse(cleaned, NumberStyles.Number, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    private static int? ParseYear(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        return int.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    private static DateOnly? ParseDate(string? raw) =>
        !string.IsNullOrWhiteSpace(raw) && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? DateOnly.FromDateTime(parsed.UtcDateTime)
            : null;
}
