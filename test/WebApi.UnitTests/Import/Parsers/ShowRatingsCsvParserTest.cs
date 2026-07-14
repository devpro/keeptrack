using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class ShowRatingsCsvParserTest
{
    [Fact]
    public void Parse_ReturnsShowIdAndRating()
    {
        const string csv = """
                            created_at,updated_at,tv_show_name,user_id,tv_show_id,rating
                            2018-06-01 20:16:07,2018-06-01 20:16:07,Prison Break,13397917,75340,2.50
                            """;

        var result = ShowRatingsCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].TvShowId.Should().Be("75340");
        result[0].Rating.Should().Be(2.50f);
    }
}
