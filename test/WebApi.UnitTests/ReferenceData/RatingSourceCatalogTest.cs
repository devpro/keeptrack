using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class RatingSourceCatalogTest
{
    [Fact]
    public void VideoGames_OfferIgdbItsCriticAggregateAndMetacritic_WithIgdbAsTheDefault()
    {
        RatingSourceCatalog.AvailableSources(ReferenceItemType.VideoGame)
            .Should().Equal(RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic, RatingSourceCatalog.Metacritic);
        RatingSourceCatalog.DefaultSource(ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Igdb);
        RatingSourceCatalog.IsSelectable(ReferenceItemType.VideoGame).Should().BeTrue();
        RatingSourceCatalog.SelectableDomains.Should().Contain(ReferenceItemType.VideoGame);
    }

    [Fact]
    public void Rawg_IsNoLongerSelectable_ButKeepsItsScale()
    {
        // RAWG stopped being the video game default, but references linked through it still carry rawg-keyed
        // values that detail pages render - and ScaleOf throws on a source it doesn't know, so dropping the
        // declaration would turn every one of those into an exception rather than a stale number.
        RatingSourceCatalog.AvailableSources(ReferenceItemType.VideoGame).Should().NotContain(RatingSourceCatalog.Rawg);
        RatingSourceCatalog.ScaleOf(RatingSourceCatalog.Rawg).Should().Be(5);
    }

    [Fact]
    public void ResolveIgnoresARawgEraOverride_SoAStoredChoiceCannotStrandAnItem()
    {
        // an admin who had selected RAWG before the switch resolves to the current default instead, which is
        // what lets the existing recompute re-stamp every item with no migration script.
        var overrides = new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.Rawg };

        RatingSourceCatalog.Resolve(overrides, ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Igdb);
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
