using System.Globalization;
using CsvHelper;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Shared row-by-row reader for TV Time files that mix genuine per-episode watch events together
/// with other row types (show-level summaries, counters, ...) in the same CSV. Each source file has
/// its own way of telling those apart, so the discriminator is supplied by the caller; everything
/// else (opening the stream, skipping rows without a season/episode, building the result) is common.
/// </summary>
internal static class RawEpisodeWatchRowParser
{
    public static List<SeenEpisodeRecord> Parse(Stream csvStream, string showIdColumn, Func<CsvReader, bool> isEpisodeWatchRow)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        csv.Read();
        csv.ReadHeader();

        var records = new List<SeenEpisodeRecord>();
        while (csv.Read())
        {
            if (!isEpisodeWatchRow(csv)) continue;

            var seasonNumber = csv.GetField("season_number");
            var episodeNumber = csv.GetField("episode_number");
            if (string.IsNullOrEmpty(seasonNumber) || string.IsNullOrEmpty(episodeNumber)) continue;

            records.Add(new SeenEpisodeRecord
            {
                ShowTitle = csv.GetField("series_name") ?? string.Empty,
                TvShowId = csv.GetField(showIdColumn),
                SeasonNumber = int.Parse(seasonNumber, CultureInfo.InvariantCulture),
                EpisodeNumber = int.Parse(episodeNumber, CultureInfo.InvariantCulture),
                WatchedAt = csv.GetField<DateTime>("created_at")
            });
        }

        return records;
    }
}
