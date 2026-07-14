using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class EpisodeCommentsCsvParserTest
{
    [Fact]
    public void Parse_ReturnsShowTitleSeasonEpisodeAndComment()
    {
        const string csv = """
                            source,episode_number,episode_id,updated_at,spoiler_count,nb_likes,depth,comment_type,lang,highlight_level,same_ip_likes,episode_season_number,id,posted_on_fb,parent_comment_id,valid,nb_points,tv_show_name,user_id,comment,created_at,posted_on_twitter,unappropriate_count,extended_comment
                            mobile,10,6347559,2018-01-07 14:38:00,0,0,1,comment,en,5,0,1,10687229,0,10266504,0,0,Dark,13397917,I think so too,2018-01-07 14:38:00,0,0,null
                            """;

        var result = EpisodeCommentsCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].ShowTitle.Should().Be("Dark");
        result[0].SeasonNumber.Should().Be(1);
        result[0].EpisodeNumber.Should().Be(10);
        result[0].Comment.Should().Be("I think so too");
    }
}
