using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a minimal synthetic TV Time GDPR export zip for the import smoke test: one followed show and one seen episode.
/// The importer tolerates every other export file being absent (<c>ReadCsvEntry</c> returns null for a missing entry), so a two-file zip is enough to create one show + one episode.
/// A per-call unique show title and TV Time show id keep every run's imported show distinct (the id drives the importer's idempotency), so the test always creates a fresh show it then deletes.
/// Never use a real personal export as a fixture (same rule as the integration suite's own builder).
/// </summary>
internal static class TvTimeImportFixtureZipBuilder
{
    public static byte[] Build(string showTitle)
    {
        var showId = Random.Shared.Next(900_000, 999_999);

        var followedShows = $"""
                             updated_at,active,notification_type,folder_id,archived,notification_offset,user_id,tv_show_id,tv_show_name,created_at,diffusion
                             2020-01-01 00:00:00,1,2,,0,1440,999,{showId},{showTitle},2020-01-01 00:00:00,original

                             """;

        var seenEpisodes = $"""
                            updated_at,tv_show_name,episode_season_number,episode_number,user_id,episode_id,source,created_at
                            2020-01-02 00:00:00,{showTitle},1,1,999,1,episode-detail,2020-01-02 00:00:00

                            """;

        using var zipStream = new MemoryStream();
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "followed_tv_show.csv", followedShows);
            WriteEntry(archive, "seen_episode_source.csv", seenEpisodes);
        }

        return zipStream.ToArray();
    }

    private static void WriteEntry(ZipArchive archive, string fileName, string content)
    {
        var entry = archive.CreateEntry(fileName);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
    }
}
