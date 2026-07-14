using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class ShowActivityRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    /// <summary>
    /// TV Time's own count of episodes seen for this show, including ones marked via bulk/season
    /// actions that never get an individual row in seen_episode_source.csv.
    /// </summary>
    [Name("nb_episodes_seen")]
    public required int EpisodesSeenCount { get; set; }
}

/// <summary>
/// Parses TV Time's user_tv_show_data.csv: per-show aggregate activity, notably a total episode
/// count that can be higher than what seen_episode_source.csv captures in detail.
/// </summary>
public static class ShowActivityCsvParser
{
    public static List<ShowActivityRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<ShowActivityRecord>().ToList();
    }
}
