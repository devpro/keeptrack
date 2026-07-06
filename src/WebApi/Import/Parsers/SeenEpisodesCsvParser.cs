using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// One episode watch event. The column names differ slightly across the several files that carry
/// this same information (see <see cref="SeenEpisodesCsvParser"/>, <see cref="LegacyEpisodeWatchCsvParser"/>,
/// <see cref="EpisodeWatchCsvParser"/>), so both naming variants are accepted here.
/// </summary>
public class SeenEpisodeRecord
{
    [Name("tv_show_name", "series_name")]
    public required string ShowTitle { get; set; }

    /// <summary>
    /// TV Time's show id, when the source file has one (the tracking-prod-records files do;
    /// seen_episode_source.csv doesn't, so this is null for records coming from that file).
    /// Lets a show be identified - and enriched with its rating/status/comments - even when it never
    /// appeared in followed_tv_show.csv. [Optional] because none of the three aliases exist at all in
    /// seen_episode_source.csv's header, and CsvHelper's header validation otherwise throws on that,
    /// even though the property itself isn't `required`.
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
/// Episodes here are only identified by show name (no show id in this file). This file alone is
/// usually far from complete - it's only written when an episode is marked watched via the
/// episode-detail screen. <see cref="LegacyEpisodeWatchCsvParser"/> and <see cref="EpisodeWatchCsvParser"/>
/// cover the much larger volume of episodes marked watched other ways.
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
