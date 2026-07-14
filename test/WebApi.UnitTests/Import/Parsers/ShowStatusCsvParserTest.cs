using System.Linq;
using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class ShowStatusCsvParserTest
{
    [Fact]
    public void Parse_ReturnsFavoriteAndForLaterStatuses()
    {
        const string csv = """
                            created_at,updated_at,tv_show_name,user_id,tv_show_id,status
                            2018-10-21 10:25:34,2018-10-21 10:25:34,Charmed,13397917,70626,for_later
                            2018-11-14 20:25:51,2018-11-14 20:25:51,ER,13397917,70761,favorite
                            """;

        var result = ShowStatusCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().HaveCount(2);
        result.Single(r => r.TvShowId == "70626").Status.Should().Be(ShowStatusCsvParser.ForLaterStatus);
        result.Single(r => r.TvShowId == "70761").Status.Should().Be(ShowStatusCsvParser.FavoriteStatus);
    }
}
