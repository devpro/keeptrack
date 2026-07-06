using System;
using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class EpisodeWatchCsvParserTest
{
    [Fact]
    public void Parse_ExtractsOnlyGenuineEpisodeWatchRows()
    {
        const string csv = """
                            s_id,user_id,episode_id,series_name,gsi,runtime,created_at,season_number,episode_number,ep_no,ep_id,s_no,key,ep_watch_count,total_movies_runtime,total_series_runtime,series_follow_count,movie_watch_count,updated_at,is_followed,most_recent_ep_watched,is_for_later,uuid,followed_at,is_archived,is_unitary,rewatch_count,bulk_type,is_special
                            258541,13397917,,Chicago Fire,,,2017-06-09 22:13:33,,,,,,user-series-e8fb922a-0799-4daf-b1b9-2d3d25f92e8e,292,,,,,2026-05-04 11:47:17,true,map[ep_id:1.1680091e+07 ep_no:18 s_no:14 uuid:40c0029d-af3f-49fb-968f-195f01df9463 watch_date:1.777895237135508e+15],false,e8fb922a-0799-4daf-b1b9-2d3d25f92e8e,,false,,,,
                            258541,13397917,8956036,Chicago Fire,watch-episode-1702296819,2520,2023-12-11 12:13:39,10,14,14,8956036,10,watch-episode-e8fb922a-0799-4daf-b1b9-2d3d25f92e8e-001e2d1e-1621-4380-8f76-8f3730dd6a01,,,,,,2023-12-11 12:13:39,,,,,,,true,,,
                            """;

        var result = EpisodeWatchCsvParser.Parse(CsvTestHelper.ToStream(csv));

        // the per-show summary row (empty "gsi") is skipped; only the "watch-episode-*" row survives
        result.Should().ContainSingle();
        result[0].ShowTitle.Should().Be("Chicago Fire");
        result[0].SeasonNumber.Should().Be(10);
        result[0].EpisodeNumber.Should().Be(14);
        result[0].WatchedAt.Should().Be(new DateTime(2023, 12, 11, 12, 13, 39));
    }
}
