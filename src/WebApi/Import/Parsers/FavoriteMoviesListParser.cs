using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

internal class ListRowRecord
{
    [Name("s_key")]
    public string? SKey { get; set; }

    [Name("objects")]
    public string? Objects { get; set; }
}

/// <summary>
/// Parses TV Time's lists-prod-lists.csv to find the movie ids in the built-in "Favorite Movies" list.
/// That one row's `objects` column is not CSV or JSON: it's a Go fmt-style dump of a slice of maps,
/// e.g. "[map[created_at:... type:movie uuid:1be8d227-...] map[... type:series id:71663] ...]".
/// </summary>
public static partial class FavoriteMoviesListParser
{
    private const string FavoriteMoviesSKey = "favorite-movies";

    public static HashSet<string> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        var objectsField = csv.GetRecords<ListRowRecord>()
            .FirstOrDefault(row => row.SKey == FavoriteMoviesSKey)
            ?.Objects;
        return ParseObjectsField(objectsField);
    }

    /// <summary>
    /// Pure parsing of the raw `objects` field content, split out so it can be unit-tested without a CSV file.
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
