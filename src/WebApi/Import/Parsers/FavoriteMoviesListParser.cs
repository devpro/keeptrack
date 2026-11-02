using System.Text.RegularExpressions;
using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
internal partial class ListRowRecord
{
    [CsvColumn("s_key")]
    public string? SKey { get; set; }

    [CsvColumn("objects")]
    public string? Objects { get; set; }
}

/// <summary>
/// Parses TV Time's lists-prod-lists.csv to find the movie ids in the built-in "Favorite Movies" list.
/// That row's `objects` column is neither CSV nor JSON but a Go fmt dump of a slice of maps,
/// such as "[map[created_at:... type:movie uuid:1be8d227-...] map[... type:series id:71663]]".
/// </summary>
public static partial class FavoriteMoviesListParser
{
    private const string FavoriteMoviesSKey = "favorite-movies";

    public static HashSet<string> Parse(Stream csvStream)
    {
        var objectsField = ImportCsv.ReadRecords<ListRowRecord>(csvStream)
            .FirstOrDefault(row => row.SKey == FavoriteMoviesSKey)
            ?.Objects;
        return ParseObjectsField(objectsField);
    }

    /// <summary>
    /// Parses the raw `objects` field, apart so it is tested without a CSV file.
    /// </summary>
    public static HashSet<string> ParseObjectsField(string? objectsField)
    {
        var uuids = new HashSet<string>();
        if (string.IsNullOrEmpty(objectsField)) return uuids;

        foreach (Match entry in EntryRegex().Matches(objectsField))
        {
            var content = entry.Groups[1].Value;
            if (!content.Contains("type:movie")) continue;

            var uuidMatch = UuidRegex().Match(content);
            if (uuidMatch.Success) uuids.Add(uuidMatch.Groups[1].Value);
        }

        return uuids;
    }

    [GeneratedRegex(@"map\[([^\[\]]*)\]")]
    private static partial Regex EntryRegex();

    [GeneratedRegex(@"uuid:([0-9a-fA-F-]{36})")]
    private static partial Regex UuidRegex();
}
