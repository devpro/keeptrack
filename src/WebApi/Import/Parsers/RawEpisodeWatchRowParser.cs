using System.Globalization;
using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Shared reader for TV Time files mixing episode watch events with other rows (show summaries, counters) in one CSV.
/// Each file tells them apart its own way, so the caller supplies the discriminator,
/// and the rest (opening the stream, skipping rows without a season or episode, building the result) is common.
/// </summary>
internal static class RawEpisodeWatchRowParser
{
    public static List<SeenEpisodeRecord> Parse(Stream csvStream, string showIdColumn, Func<CsvReader, bool> isEpisodeWatchRow)
    {
        using var csv = ImportCsv.Open(csvStream);

        var records = new List<SeenEpisodeRecord>();
        while (csv.Read())
        {
            if (!isEpisodeWatchRow(csv)) continue;

            var seasonNumber = csv.GetString("season_number");
            var episodeNumber = csv.GetString("episode_number");
            if (string.IsNullOrEmpty(seasonNumber) || string.IsNullOrEmpty(episodeNumber)) continue;

            records.Add(new SeenEpisodeRecord
            {
                ShowTitle = csv.GetString("series_name") ?? string.Empty,
                TvShowId = csv.GetString(showIdColumn),
                SeasonNumber = int.Parse(seasonNumber, CultureInfo.InvariantCulture),
                EpisodeNumber = int.Parse(episodeNumber, CultureInfo.InvariantCulture),
                WatchedAt = csv.Parse<DateTime>("created_at")
            });
        }

        return records;
    }
}
