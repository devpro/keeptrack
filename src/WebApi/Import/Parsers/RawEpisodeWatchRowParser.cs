using System.Globalization;
using CsvHelper;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Shared reader for TV Time files mixing episode watch events with other rows (show summaries, counters) in one CSV.
/// Each file tells them apart its own way, so the caller supplies the discriminator, and the rest (opening the stream, skipping rows without a season or episode, building the result) is common.
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
