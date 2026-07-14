using System;
using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class MovieTrackingEventsCsvParserTest
{
    private const string Header =
        "series_name,uuid,type-uuid-n,watch_count,type,updated_at,created_at,series_id,user_id,watches,movie_name,runtime,entity_type,alpha_range_key,follow_date_range_key,release_date,release_date_range_key,rewatch_count,series_uuid,season_number,episode_id,watch_date,episode_number,total_movies_runtime,total_series_runtime,country,bulk_type,watched_episode_range_key,watch_date_range_key,unitarian";

    [Fact]
    public void Parse_ExtractsWatchTowatchAndFollowMovieRows_AndSkipsEpisodeRows()
    {
        var csv = string.Join('\n',
            Header,
            // watch: entity_type "movie", type "watch"
            ",008d62e0-8f51-496d-bbc4-278866bbe82d,watch-008d62e0-0,,watch,2020-02-11 23:09:28,2020-02-11 23:09:28,,13397917,,Fury,,movie,,,0001-01-01 00:00:00,,0,,,,,,,,,,,,",
            // towatch: entity_type "movie", type "towatch"
            ",05807f03-e989-47e3-8494-7964df0a7f12,towatch-05807f03,,towatch,2022-07-07 22:55:23,2022-07-07 22:55:23,,13397917,,Thor: Love and Thunder,7140,movie,,,2022-07-13 00:00:00,,,,,,,,,,,,,,",
            // follow: entity_type "movie", type "follow" (no watch/towatch signal, still exists)
            ",0075d259-c3b2-43ad-a481-1b3af1ef80da,follow-0075d259-0,,follow,2023-10-19 22:30:22,2023-10-19 22:30:22,,13397917,,Centurion,5520,movie,,,2009-07-21 00:00:00,,,,,,,,,,,,,,",
            // a genuine episode watch row (entity_type "episode") must be skipped entirely
            "Chicago Fire,01ef3f79-a57b-4913-861e-1c9c3a4f7122,watch-01ef3f79-0,,watch,2021-06-22 11:22:30,2021-06-22 11:22:30,258541,13397917,,,,episode,,,,,,e8fb922a,9,8305607,1624360950,16,,,us,,watched-episode,watch-date-1624360950,true");

        var result = MovieTrackingEventsCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().HaveCount(3);
        result.Should().Contain(r => r.MovieName == "Fury" && r.EventType == MovieTrackingEventType.Watched && r.CreatedAt == new DateTime(2020, 2, 11, 23, 9, 28));
        result.Should().Contain(r => r.MovieName == "Thor: Love and Thunder" && r.EventType == MovieTrackingEventType.WantToWatch);
        result.Should().Contain(r => r.MovieName == "Centurion" && r.EventType == MovieTrackingEventType.Followed);
    }
}
