using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
public partial class FollowedShowRecord
{
    [CsvColumn("tv_show_id")]
    public required string TvShowId { get; set; }

    [CsvColumn("tv_show_name")]
    public required string Title { get; set; }
}

/// <summary>
/// Parses TV Time's followed_tv_show.csv, the master list of a user's TV shows.
/// </summary>
public static class FollowedShowsCsvParser
{
    public static List<FollowedShowRecord> Parse(Stream csvStream)
    {
        return ImportCsv.ReadRecords<FollowedShowRecord>(csvStream);
    }
}
