using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class ShowActivityCsvParserTest
{
    [Fact]
    public void Parse_ReturnsShowIdAndEpisodesSeenCount()
    {
        const string csv = """
                            user_id,tv_show_id,is_followed,is_favorited,nb_episodes_seen,tv_show_name
                            13397917,258541,1,0,291,Chicago Fire
                            """;

        var result = ShowActivityCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].TvShowId.Should().Be("258541");
        result[0].EpisodesSeenCount.Should().Be(291);
    }
}
