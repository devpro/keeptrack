namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Parses TV Time's tracking-prod-records-v2.csv: the newer-generation replacement for
/// tracking-prod-records.csv, same idea - a generic event log with an individually dated row per
/// episode watch, identified by its "gsi" column starting with "watch-episode-". Other row types in
/// this file (one per-show summary row with an aggregate "most_recent_ep_watched" field) are skipped.
/// </summary>
public static class EpisodeWatchCsvParser
{
    private const string EpisodeWatchPrefix = "watch-episode-";

    public static List<SeenEpisodeRecord> Parse(Stream csvStream) =>
        RawEpisodeWatchRowParser.Parse(csvStream, "s_id", csv => (csv.GetField("gsi") ?? string.Empty).StartsWith(EpisodeWatchPrefix, StringComparison.Ordinal));
}
