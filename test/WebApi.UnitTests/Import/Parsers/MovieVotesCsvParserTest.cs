using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class MovieVotesCsvParserTest
{
    [Fact]
    public void Parse_SkipsRowsWithoutAMovieName()
    {
        const string csv = """
                            uuid,user_id,episode_id,movie_name,vote_key,series_name,season_number,episode_number
                            4273cc26-528e-463e-814e-534e3e50eceb,13397917,0,Bohemian Rhapsody,4273cc26-528e-463e-814e-534e3e50eceb-13397917-3,,,
                            aaaaaaaa-528e-463e-814e-534e3e50eceb,13397917,4383263,,aaaaaaaa-13397917-3,The Americans,1,1
                            """;

        var result = MovieVotesCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].Uuid.Should().Be("4273cc26-528e-463e-814e-534e3e50eceb");
        result[0].MovieName.Should().Be("Bohemian Rhapsody");
    }

    [Fact]
    public void Parse_HandlesTheDifferentColumnOrderOfTheLiveVotesFile()
    {
        const string csv = """
                            vote_key,episode_id,user_id,uuid,movie_name
                            46166a01-b4cf-41ec-8a3b-51e1adbe9c44-13397917-29,0,13397917,46166a01-b4cf-41ec-8a3b-51e1adbe9c44,Terminator: Dark Fate
                            """;

        var result = MovieVotesCsvParser.Parse(CsvTestHelper.ToStream(csv));

        result.Should().ContainSingle();
        result[0].MovieName.Should().Be("Terminator: Dark Fate");
    }
}
