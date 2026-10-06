namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Parses TV Time's tracking-prod-records-v2.csv, the newer form of tracking-prod-records.csv:
/// an event log with a dated row per episode watch, whose "gsi" column starts with "watch-episode-".
/// Other rows, such as a summary per show with "most_recent_ep_watched", are skipped.
/// </summary>
public static class EpisodeWatchCsvParser
{
    private const string EpisodeWatchPrefix = "watch-episode-";

    public static List<SeenEpisodeRecord> Parse(Stream csvStream) =>
        RawEpisodeWatchRowParser.Parse(csvStream, "s_id", csv => (csv.GetField("gsi") ?? string.Empty).StartsWith(EpisodeWatchPrefix, StringComparison.Ordinal));
}
