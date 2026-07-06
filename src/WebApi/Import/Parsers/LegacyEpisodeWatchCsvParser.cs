using System.Collections.Generic;
using System.IO;
using CsvHelper;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Parses TV Time's tracking-prod-records.csv: a generic, older-generation event log that includes
/// (among many other event types) an individually dated row per episode watch. Far more complete
/// than seen_episode_source.csv, which only covers episodes marked watched via the episode-detail
/// screen. A genuine episode watch row has type "watch" and entity_type "episode"; every other row
/// type (show-level counters, "last episode watched" summaries, ...) is skipped.
/// </summary>
public static class LegacyEpisodeWatchCsvParser
{
    public static List<SeenEpisodeRecord> Parse(Stream csvStream) =>
        RawEpisodeWatchRowParser.Parse(csvStream, csv => csv.GetField("type") == "watch" && csv.GetField("entity_type") == "episode");
}
