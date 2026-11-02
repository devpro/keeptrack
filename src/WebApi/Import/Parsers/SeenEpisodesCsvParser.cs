using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// One episode watch event.
/// Column names differ slightly across the files carrying it (<see cref="SeenEpisodesCsvParser"/>, <see cref="LegacyEpisodeWatchCsvParser"/>, <see cref="EpisodeWatchCsvParser"/>),
/// so both variants are accepted.
/// </summary>
[CsvRecord]
public partial class SeenEpisodeRecord
{
    [CsvColumn("tv_show_name", "series_name")]
    public required string ShowTitle { get; set; }

    /// <summary>
    /// TV Time's show id, when the file has one: the tracking files do, seen_episode_source.csv does not.
    /// It identifies a show, and brings its rating, status and comments, even when absent from followed_tv_show.csv.
    /// Optional, since no alias exists in seen_episode_source.csv's header, and CsvHelper throws on a missing column unless it is marked so, nullable or not.
    /// </summary>
    [CsvColumn("tv_show_id", "series_id", "s_id", Optional = true)]
    public string? TvShowId { get; set; }

    [CsvColumn("episode_season_number", "season_number")]
    public required int SeasonNumber { get; set; }

    [CsvColumn("episode_number")]
    public required int EpisodeNumber { get; set; }

    [CsvColumn("created_at")]
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
        return ImportCsv.ReadRecords<SeenEpisodeRecord>(csvStream);
    }
}
