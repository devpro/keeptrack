using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class RatingSourceCatalogTest
{
    [Fact]
    public void VideoGames_OfferRawgAndMetacritic_WithRawgAsTheDefault()
    {
        RatingSourceCatalog.AvailableSources(ReferenceItemType.VideoGame)
            .Should().Equal(RatingSourceCatalog.Rawg, RatingSourceCatalog.Metacritic);
        RatingSourceCatalog.DefaultSource(ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Rawg);
        RatingSourceCatalog.IsSelectable(ReferenceItemType.VideoGame).Should().BeTrue();
        RatingSourceCatalog.SelectableDomains.Should().Contain(ReferenceItemType.VideoGame);
    }

    [Theory]
    [InlineData(ReferenceItemType.Movie)]
    [InlineData(ReferenceItemType.TvShow)]
    public void MoviesAndTvShows_OfferTmdbAndImdb_WithTmdbAsTheDefault(ReferenceItemType domain)
    {
        RatingSourceCatalog.AvailableSources(domain).Should().Equal(RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb);
        RatingSourceCatalog.DefaultSource(domain).Should().Be(RatingSourceCatalog.Tmdb);
        RatingSourceCatalog.IsSelectable(domain).Should().BeTrue();
        RatingSourceCatalog.SelectableDomains.Should().Contain(domain);
    }

    [Theory]
    [InlineData(ReferenceItemType.Book)]
    [InlineData(ReferenceItemType.Album)]
    public void SingleSourceDomains_AreNotYetAdminSelectable(ReferenceItemType domain)
    {
        // these have only one source today, so there's nothing to choose - they join the catalog when they
        // gain a second source, the same way movies/TV did once IMDb landed.
        RatingSourceCatalog.IsSelectable(domain).Should().BeFalse();
        RatingSourceCatalog.AvailableSources(domain).Should().BeEmpty();
    }
}
