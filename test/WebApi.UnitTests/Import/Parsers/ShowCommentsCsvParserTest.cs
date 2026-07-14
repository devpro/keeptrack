using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class ShowCommentsCsvParserTest
{
    [Fact]
    public void Parse_PreservesMultiLineQuotedComment()
    {
        const string csv = "spoiler_count,nb_likes,lang,tv_show_name,created_at,parent_comment_id,source,only_to_fans,user_id,posted_on_fb,posted_on_twitter,comment_type,highlight_level,extended_comment,id,tv_show_id,comment,updated_at,unappropriate_count,depth,valid,same_ip_likes,featured\n"
                          + "0,3,en,Dark,2019-05-12 18:45:53,,mobile,1,13397917,0,0,comment,5,null,1244578,334824,\"Amazing show, really worth watching.\nI don't know another show like this one.\",2019-05-12 18:45:53,0,0,1,0,0\n";

        var result = ShowCommentsCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].TvShowId.Should().Be("334824");
        result[0].Comment.Should().Be("Amazing show, really worth watching.\nI don't know another show like this one.");
    }
}
