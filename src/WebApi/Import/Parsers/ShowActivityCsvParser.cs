using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class ShowActivityRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    /// <summary>
    /// TV Time's count of episodes seen for this show, including those marked by bulk or season actions, which get no row in seen_episode_source.csv.
    /// </summary>
    [Name("nb_episodes_seen")]
    public required int EpisodesSeenCount { get; set; }
}

/// <summary>
/// Parses TV Time's user_tv_show_data.csv: activity totals per show, notably an episode count that can exceed what seen_episode_source.csv details.
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
