using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic TV Time GDPR export zip for tests: representative rows of each file
/// shape the importer reads, for a single fake show/movie. Never use the real personal export in tests.
/// </summary>
internal static class TvTimeFixtureZipBuilder
{
    public const string ShowTitle = "Keeptrack Integration Test Show";

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
            ["tv_show_rate.csv"] = $"""
                                    created_at,updated_at,tv_show_name,user_id,tv_show_id,rating
                                    2020-01-01 00:00:00,2020-01-01 00:00:00,{ShowTitle},999,999001,4.5

                                    """,
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
}
