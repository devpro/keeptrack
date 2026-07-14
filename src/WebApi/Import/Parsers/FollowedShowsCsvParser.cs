using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class FollowedShowRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    [Name("tv_show_name")]
    public required string Title { get; set; }
}

/// <summary>
/// Parses TV Time's followed_tv_show.csv, the master list of a user's TV shows.
/// </summary>
public static class FollowedShowsCsvParser
{
    public static List<FollowedShowRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<FollowedShowRecord>().ToList();
    }
}
