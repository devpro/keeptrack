using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// One episode watch event.
/// Column names differ slightly across the files carrying it (<see cref="SeenEpisodesCsvParser"/>, <see cref="LegacyEpisodeWatchCsvParser"/>, <see cref="EpisodeWatchCsvParser"/>), so both variants are accepted.
/// </summary>
public class SeenEpisodeRecord
{
    [Name("tv_show_name", "series_name")]
    public required string ShowTitle { get; set; }

    /// <summary>
    /// TV Time's show id, when the file has one: the tracking files do, seen_episode_source.csv does not.
    /// It identifies a show, and brings its rating, status and comments, even when absent from followed_tv_show.csv.
    /// [Optional], since no alias exists in seen_episode_source.csv's header, and CsvHelper's header validation would throw although the property is nullable.
    /// </summary>
    [Name("tv_show_id", "series_id", "s_id")]
    [Optional]
    public string? TvShowId { get; set; }

    [Name("episode_season_number", "season_number")]
    public required int SeasonNumber { get; set; }

    [Name("episode_number")]
    public required int EpisodeNumber { get; set; }

    [Name("created_at")]
    public required DateTime WatchedAt { get; set; }
}

/// <summary>
/// Parses TV Time's seen_episode_source.csv: one row per episode watch event, with a date.
/// Episodes are identified by show name only, with no show id.
/// This file alone is far from complete, written only when an episode is marked watched from the episode screen.
/// <see cref="LegacyEpisodeWatchCsvParser"/> and <see cref="EpisodeWatchCsvParser"/> cover the many episodes marked watched other ways.
/// </summary>
public static class SeenEpisodesCsvParser
{
    public static List<SeenEpisodeRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<SeenEpisodeRecord>().ToList();
    }
}
