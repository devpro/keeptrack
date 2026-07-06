using System;
using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class LegacyEpisodeWatchCsvParserTest
{
    [Fact]
    public void Parse_ExtractsOnlyGenuineEpisodeWatchRows()
    {
        const string csv = """
                            series_name,uuid,type-uuid-n,watch_count,type,updated_at,created_at,series_id,user_id,watches,movie_name,runtime,entity_type,alpha_range_key,follow_date_range_key,release_date,release_date_range_key,rewatch_count,series_uuid,season_number,episode_id,watch_date,episode_number,total_movies_runtime,total_series_runtime,country,bulk_type,watched_episode_range_key,watch_date_range_key,unitarian
                            Chicago Fire,e8fb922a-0799-4daf-b1b9-2d3d25f92e8e,count-watch-episode-series-e8fb922a-0799-4daf-b1b9-2d3d25f92e8e,16,count-watch-episode-series,2021-10-28 10:53:37,2021-01-19 14:37:14,258541,13397917,,,,,,,,,,,,,,,,,,,,,
                            Chicago Fire,01ef3f79-a57b-4913-861e-1c9c3a4f7122,watch-01ef3f79-a57b-4913-861e-1c9c3a4f7122-0,,watch,2021-06-22 11:22:30,2021-06-22 11:22:30,258541,13397917,,,,episode,,,,,,e8fb922a-0799-4daf-b1b9-2d3d25f92e8e,9,8305607,1624360950,16,,,us,,watched-episode-e8fb922a-0799-4daf-b1b9-2d3d25f92e8e-01ef3f79-a57b-4913-861e-1c9c3a4f7122,watch-date-1624360950,true
                            """;

        var result = LegacyEpisodeWatchCsvParser.Parse(CsvTestHelper.ToStream(csv));

        // the "count-watch-episode-series" summary row is skipped; only the "watch"/"episode" row survives
        result.Should().ContainSingle();
        result[0].ShowTitle.Should().Be("Chicago Fire");
        result[0].SeasonNumber.Should().Be(9);
        result[0].EpisodeNumber.Should().Be(16);
        result[0].WatchedAt.Should().Be(new DateTime(2021, 6, 22, 11, 22, 30));
    }
}
