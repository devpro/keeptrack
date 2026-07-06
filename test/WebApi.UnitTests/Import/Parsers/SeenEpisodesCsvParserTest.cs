using System;
using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class SeenEpisodesCsvParserTest
{
    [Fact]
    public void Parse_ReturnsShowTitleSeasonEpisodeAndWatchedDate()
    {
        const string csv = """
                            updated_at,tv_show_name,episode_season_number,episode_number,user_id,episode_id,source,created_at
                            2018-10-08 20:35:17,Charmed,1,1,13397917,16029,episode-detail,2018-10-08 20:35:17
                            """;

        var result = SeenEpisodesCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].ShowTitle.Should().Be("Charmed");
        result[0].SeasonNumber.Should().Be(1);
        result[0].EpisodeNumber.Should().Be(1);
        result[0].WatchedAt.Should().Be(new DateTime(2018, 10, 8, 20, 35, 17));
    }
}
