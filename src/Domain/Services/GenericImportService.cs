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
/// Parses a generic CSV import into review rows.
/// Pure: bytes in, rows out, with no repository access, the caller computing <c>alreadyImportedReferences</c> so this tests without a database.
///
/// The store-agnostic counterpart of <see cref="AmazonOrderPreviewService"/>.
/// Rather than hardcoding a vendor, columns and a "is this a book" guess, it reads a canonical,
/// case-insensitive column set, all optional except the title, that the user reshapes an export into.
/// A "Type" column, when present, sets each row's media type, which prefills the per-row picker.
/// </summary>
public static class GenericImportService
{
    private sealed class GenericImportRecord
    {
        // the one required column, with the common retailer header as an alias
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

        // the store name, which becomes the copy's Vendor only, unlike Website, which feeds its Reference
        [Optional]
        [Name("Vendor", "Store")]
        public string? Vendor { get; set; }

        // free-text label (product or order URL, seller) for the copy's Reference, never its Vendor
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
    /// Formats an imported row's owned copy <c>Reference</c>,
    /// which is human-readable and also the exact dedup key <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/> looks for on a re-import.
    /// The leading label is the <paramref name="website"/> column, never the vendor, so the reference stays independent of the Vendor field.
    /// Uniqueness comes from the order id plus the product id, or the title when the file has none, never from the label.
    /// One order often holds several items, and the order id alone would skip every other item once one was imported,
    /// as the ASIN and the PSN product name prevent in the other importers.
    /// </summary>
    public static string FormatReference(string? website, string? orderId, string? productId, string title)
    {
        var prefix = string.IsNullOrWhiteSpace(website) ? "Order" : $"{website.Trim()} order";
        var order = string.IsNullOrWhiteSpace(orderId) ? "?" : orderId.Trim();
        var descriptor = string.IsNullOrWhiteSpace(productId) ? title : productId.Trim();
        return $"{prefix} {order} ({descriptor})";
    }

    /// <summary>
    /// Keeps the export's original listing text on an item this import creates.
    /// Reference linking may overwrite the title (and a book's ISBN), and the user may have edited the title before commit.
    /// Only used on creation, since an existing item's provenance is not this import's to invent.
    /// <paramref name="isbn"/> is null for every domain but books.
    /// </summary>
    public static string BuildProvenanceNotes(string? vendor, string sourceTitle, string? isbn)
    {
        var source = string.IsNullOrWhiteSpace(vendor) ? "import" : vendor.Trim();
        var lines = new List<string> { $"Title from {source}: {sourceTitle}" };
        if (!string.IsNullOrWhiteSpace(isbn)) lines.Add($"ISBN from {source}: {isbn.Trim()}");
        return string.Join('\n', lines);
    }

    /// <summary>
    /// Maps a free-text "Type" value onto <see cref="ImportMediaType"/>, tolerating the spellings a user types ("TV Show", "Video Game", "Film", "Jeu").
    /// Null for a blank or unrecognized value, which the review UI turns into a required pick rather than a guess.
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
    /// Strips a leading apostrophe, a spreadsheet's guard against formula injection (the literal <c>'-5</c>), before parsing.
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
