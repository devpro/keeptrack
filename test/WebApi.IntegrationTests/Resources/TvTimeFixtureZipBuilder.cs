using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic TV Time GDPR export zip for tests: representative rows of each file
/// shape the importer reads, for a single fake show/movie. Never use the real personal export in tests.
/// </summary>
internal static class TvTimeFixtureZipBuilder
{
    public const string ShowTitle = "Keeptrack Integration Test Show";

    /// <summary>
    /// A show with genuine watch history and a rating, but that never appears in followed_tv_show.csv -
    /// this is exactly the real-world case ("The Pitt" in the user's own export) that was silently
    /// dropped before: the importer must still create it and import its episode, not skip it.
    /// </summary>
    public const string OrphanShowTitle = "Keeptrack Orphan Show";

    public const string MovieTitle = "Keeptrack Integration Test Movie";

    private const string MovieUuid = "11111111-1111-1111-1111-111111111111";

    public static byte[] Build()
    {
        var entries = new Dictionary<string, string>
        {
            ["followed_tv_show.csv"] = $"""
                                        updated_at,active,notification_type,folder_id,archived,notification_offset,user_id,tv_show_id,tv_show_name,created_at,diffusion
                                        2020-01-01 00:00:00,1,2,,0,1440,999,999001,{ShowTitle},2020-01-01 00:00:00,original

                                        """,
            ["seen_episode_source.csv"] = $"""
                                           updated_at,tv_show_name,episode_season_number,episode_number,user_id,episode_id,source,created_at
                                           2020-01-02 00:00:00,{ShowTitle},1,1,999,1,episode-detail,2020-01-02 00:00:00
                                           2020-01-03 00:00:00,{ShowTitle},1,2,999,2,episode-detail,2020-01-03 00:00:00

                                           """,
            // covers episodes marked watched other ways, which seen_episode_source.csv alone misses (the real bug
            // this fixture guards against): one extra episode each from the legacy and current tracking exports.
            ["tracking-prod-records.csv"] = BuildCsv(
                ["series_name", "uuid", "type-uuid-n", "watch_count", "type", "updated_at", "created_at", "series_id", "user_id",
                    "watches", "movie_name", "runtime", "entity_type", "alpha_range_key", "follow_date_range_key", "release_date",
                    "release_date_range_key", "rewatch_count", "series_uuid", "season_number", "episode_id", "watch_date",
                    "episode_number", "total_movies_runtime", "total_series_runtime", "country", "bulk_type",
                    "watched_episode_range_key", "watch_date_range_key", "unitarian"],
                new Dictionary<string, string>
                {
                    ["series_name"] = ShowTitle, ["uuid"] = "aaaa", ["type-uuid-n"] = "count-watch-episode-series-aaaa",
                    ["type"] = "count-watch-episode-series", ["created_at"] = "2020-01-04 00:00:00", ["series_id"] = "999001", ["user_id"] = "999"
                },
                new Dictionary<string, string>
                {
                    ["series_name"] = ShowTitle, ["uuid"] = "bbbb", ["type-uuid-n"] = "watch-bbbb-0", ["type"] = "watch",
                    ["created_at"] = "2020-01-04 00:00:00", ["series_id"] = "999001", ["user_id"] = "999", ["entity_type"] = "episode",
                    ["season_number"] = "1", ["episode_number"] = "3"
                },
                // movie watch event: the only source of a movie's watched date (confirmed against a real
                // export - the rating/emotion vote files never carry one)
                new Dictionary<string, string>
                {
                    ["uuid"] = "movie-watch-1", ["type"] = "watch", ["created_at"] = "2020-01-07 00:00:00",
                    ["user_id"] = "999", ["movie_name"] = MovieTitle, ["entity_type"] = "movie"
                }),
            ["tracking-prod-records-v2.csv"] = BuildCsv(
                ["s_id", "user_id", "episode_id", "series_name", "gsi", "runtime", "created_at", "season_number", "episode_number",
                    "ep_no", "ep_id", "s_no", "key", "ep_watch_count", "total_movies_runtime", "total_series_runtime",
                    "series_follow_count", "movie_watch_count", "updated_at", "is_followed", "most_recent_ep_watched", "is_for_later",
                    "uuid", "followed_at", "is_archived", "is_unitary", "rewatch_count", "bulk_type", "is_special"],
                new Dictionary<string, string>
                {
                    ["s_id"] = "999001", ["user_id"] = "999", ["series_name"] = ShowTitle, ["created_at"] = "2020-01-01 00:00:00",
                    ["key"] = "user-series-999001", ["ep_watch_count"] = "4", ["updated_at"] = "2020-01-05 00:00:00", ["is_followed"] = "true",
                    ["uuid"] = "999001-summary", ["is_archived"] = "false"
                },
                new Dictionary<string, string>
                {
                    ["s_id"] = "999001", ["user_id"] = "999", ["episode_id"] = "4", ["series_name"] = ShowTitle,
                    ["gsi"] = "watch-episode-1578182400", ["created_at"] = "2020-01-05 00:00:00", ["season_number"] = "2",
                    ["episode_number"] = "1", ["key"] = "watch-episode-999001-cccc", ["updated_at"] = "2020-01-05 00:00:00", ["is_unitary"] = "true"
                },
                // OrphanShowTitle: deliberately has NO row in followed_tv_show.csv
                new Dictionary<string, string>
                {
                    ["s_id"] = "999003", ["user_id"] = "999", ["episode_id"] = "5", ["series_name"] = OrphanShowTitle,
                    ["gsi"] = "watch-episode-1578268800", ["created_at"] = "2020-01-06 00:00:00", ["season_number"] = "1",
                    ["episode_number"] = "1", ["key"] = "watch-episode-999003-dddd", ["updated_at"] = "2020-01-06 00:00:00", ["is_unitary"] = "true"
                }),
            ["user_tv_show_data.csv"] = $"""
                                         user_id,tv_show_id,is_followed,is_favorited,nb_episodes_seen,tv_show_name
                                         999,999001,1,1,5,{ShowTitle}

                                         """,
            ["tv_show_rate.csv"] = BuildCsv(
                ["created_at", "updated_at", "tv_show_name", "user_id", "tv_show_id", "rating"],
                new Dictionary<string, string>
                {
                    ["created_at"] = "2020-01-01 00:00:00", ["updated_at"] = "2020-01-01 00:00:00", ["tv_show_name"] = ShowTitle,
                    ["user_id"] = "999", ["tv_show_id"] = "999001", ["rating"] = "4.5"
                },
                new Dictionary<string, string>
                {
                    ["created_at"] = "2020-01-06 00:00:00", ["updated_at"] = "2020-01-06 00:00:00", ["tv_show_name"] = OrphanShowTitle,
                    ["user_id"] = "999", ["tv_show_id"] = "999003", ["rating"] = "3.5"
                }),
            ["user_show_special_status.csv"] = $"""
                                                created_at,updated_at,tv_show_name,user_id,tv_show_id,status
                                                2020-01-01 00:00:00,2020-01-01 00:00:00,{ShowTitle},999,999001,favorite

                                                """,
            ["show_comment.csv"] = $"""
                                    spoiler_count,nb_likes,lang,tv_show_name,created_at,parent_comment_id,source,only_to_fans,user_id,posted_on_fb,posted_on_twitter,comment_type,highlight_level,extended_comment,id,tv_show_id,comment,updated_at,unappropriate_count,depth,valid,same_ip_likes,featured
                                    0,0,en,{ShowTitle},2020-01-01 00:00:00,,mobile,1,999,0,0,comment,5,null,1,999001,Great show,2020-01-01 00:00:00,0,0,1,0,0

                                    """,
            ["episode_comment.csv"] = $"""
                                       source,episode_number,episode_id,updated_at,spoiler_count,nb_likes,depth,comment_type,lang,highlight_level,same_ip_likes,episode_season_number,id,posted_on_fb,parent_comment_id,valid,nb_points,tv_show_name,user_id,comment,created_at,posted_on_twitter,unappropriate_count,extended_comment
                                       mobile,1,1,2020-01-02 00:00:00,0,0,1,comment,en,5,0,1,1,0,,0,0,{ShowTitle},999,Great pilot,2020-01-02 00:00:00,0,0,null

                                       """,
            ["ratings-v2-prod-votes.csv"] = $"""
                                             uuid,user_id,episode_id,movie_name,vote_key,series_name,season_number,episode_number
                                             {MovieUuid},999,0,{MovieTitle},{MovieUuid}-999-3,,,

                                             """,
            ["lists-prod-lists.csv"] = $"""
                                        s_key,user_id,objects,name,is_public,created_at,ordering,type,description,lists,list_count
                                        favorite-movies,999,"[map[created_at:1.577836800e+09 type:movie uuid:{MovieUuid}]]",,false,2020-01-01 00:00:00,0,list,,,

                                        """
        };

        using var zipStream = new MemoryStream();
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (fileName, content) in entries)
            {
                var entry = archive.CreateEntry(fileName);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(content);
            }
        }

        return zipStream.ToArray();
    }

    /// <summary>
    /// Builds a CSV from an explicit header list and one dictionary of column values per row (columns
    /// not present in a row default to empty) - avoids manually counting commas for wide, mostly-empty rows.
    /// </summary>
    private static string BuildCsv(string[] headers, params Dictionary<string, string>[] rows)
    {
        var lines = new List<string> { string.Join(',', headers) };
        lines.AddRange(rows.Select(row => string.Join(',', headers.Select(h => row.GetValueOrDefault(h, string.Empty)))));
        return string.Join('\n', lines) + '\n';
    }
}
