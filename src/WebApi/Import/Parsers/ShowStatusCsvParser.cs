using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
public partial class ShowStatusRecord
{
    [CsvColumn("tv_show_id")]
    public required string TvShowId { get; set; }

    /// <summary>
    /// TV Time status value, such as "favorite" or "for_later".
    /// </summary>
    [CsvColumn("status")]
    public required string Status { get; set; }
}

/// <summary>
/// Parses TV Time's user_show_special_status.csv: the favorite or for_later status per show.
/// </summary>
public static class ShowStatusCsvParser
{
    public const string FavoriteStatus = "favorite";

    public static List<ShowStatusRecord> Parse(Stream csvStream)
    {
        return ImportCsv.ReadRecords<ShowStatusRecord>(csvStream);
    }
}
