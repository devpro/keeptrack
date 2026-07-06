using System.Collections.Generic;
using System.IO;
using System.Linq;
using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class ShowStatusRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    /// <summary>
    /// TV Time status value, e.g. "favorite" or "for_later".
    /// </summary>
    [Name("status")]
    public required string Status { get; set; }
}

/// <summary>
/// Parses TV Time's user_show_special_status.csv: favorite/for_later status per show.
/// </summary>
public static class ShowStatusCsvParser
{
    public const string FavoriteStatus = "favorite";

    public const string ForLaterStatus = "for_later";

    public static List<ShowStatusRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<ShowStatusRecord>().ToList();
    }
}
