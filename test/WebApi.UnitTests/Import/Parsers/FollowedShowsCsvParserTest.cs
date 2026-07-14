using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class FollowedShowsCsvParserTest
{
    [Fact]
    public void Parse_ReturnsShowIdAndTitle()
    {
        const string csv = """
                            updated_at,active,notification_type,folder_id,archived,notification_offset,user_id,tv_show_id,tv_show_name,created_at,diffusion
                            2017-12-23 22:16:20,1,2,,0,1440,13397917,70327,Buffy the Vampire Slayer,2017-12-23 22:16:20,original
                            """;

        var result = FollowedShowsCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].TvShowId.Should().Be("70327");
        result[0].Title.Should().Be("Buffy the Vampire Slayer");
    }
}
