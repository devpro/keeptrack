namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Parses TV Time's tracking-prod-records.csv: an older event log holding, among other events, a dated row per episode watch.
/// Far more complete than seen_episode_source.csv, which only covers episodes marked watched from the episode screen.
/// An episode watch row has type "watch" and entity_type "episode", and every other row (show counters, "last episode watched" summaries) is skipped.
/// </summary>
public static class LegacyEpisodeWatchCsvParser
{
    public static List<SeenEpisodeRecord> Parse(Stream csvStream) =>
        RawEpisodeWatchRowParser.Parse(csvStream, "series_id", csv => csv.GetField("type") == "watch" && csv.GetField("entity_type") == "episode");
}
