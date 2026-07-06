using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class SeenEpisodeRecord
{
    [Name("tv_show_name")]
    public required string ShowTitle { get; set; }

    [Name("episode_season_number")]
    public required int SeasonNumber { get; set; }

    [Name("episode_number")]
    public required int EpisodeNumber { get; set; }

    [Name("created_at")]
    public required DateTime WatchedAt { get; set; }
}

/// <summary>
/// Parses TV Time's seen_episode_source.csv: one row per episode watch event, with a date.
/// Episodes here are only identified by show name (no show id in this file).
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
