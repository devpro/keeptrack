using AwesomeAssertions;
using Keeptrack.WebApi.Import.Parsers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import.Parsers;

[Trait("Category", "UnitTests")]
public class FavoriteMoviesListParserTest
{
    [Fact]
    public void ParseObjectsField_ExtractsOnlyMovieUuids()
    {
        const string objectsField = "[map[created_at:1.566819863e+09 type:movie uuid:1be8d227-5d39-4561-8dfa-7520b8c51d0f] " +
                                     "map[created_at:1.563396726e+09 id:70761 type:series] " +
                                     "map[created_at:1.586728877e+09 type:movie uuid:f891ce51-fcd0-47ff-b05d-7131efafa20e]]";

        var result = FavoriteMoviesListParser.ParseObjectsField(objectsField);

        result.Should().BeEquivalentTo(["1be8d227-5d39-4561-8dfa-7520b8c51d0f", "f891ce51-fcd0-47ff-b05d-7131efafa20e"]);
    }

    [Fact]
    public void ParseObjectsField_IgnoresSeriesEntriesThatAlsoCarryAUuid()
    {
        const string objectsField = "[map[created_at:1.729463362e+09 id:269586 type:series uuid:39fe9fe1-5dc7-4b4d-92f2-1b536c17f0ed]]";

        var result = FavoriteMoviesListParser.ParseObjectsField(objectsField);

        result.Should().BeEmpty();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ParseObjectsField_ReturnsEmptySet_WhenFieldIsMissing(string? objectsField)
    {
        var result = FavoriteMoviesListParser.ParseObjectsField(objectsField);

        result.Should().BeEmpty();
    }
}
