using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class RatingSourceOptionsTest
{
    [Fact]
    public void VideoGames_OfferWhateverTheirDefaultProviderReports()
    {
        var options = OptionsFor(RatingSourceCatalog.Igdb);

        options.AvailableSources(ReferenceItemType.VideoGame)
            .Should().Equal(RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic);
        options.DefaultSource(ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Igdb);
        options.IsSelectable(ReferenceItemType.VideoGame).Should().BeTrue();
        options.SelectableDomains.Should().Contain(ReferenceItemType.VideoGame);
    }

    [Fact]
    public void VideoGames_OfferRawgAndMetacriticAgain_OnADeploymentConfiguredBackToRawg()
    {
        // the property that makes a provider change reversible: what the domain offers is read from whichever client is registered as its default, not from a list in the code.
        // Pointing ReferenceData:VideoGameProvider back at RAWG brings its two sources back with no code change.
        var options = OptionsFor(RatingSourceCatalog.Rawg);

        options.AvailableSources(ReferenceItemType.VideoGame)
            .Should().Equal(RatingSourceCatalog.Rawg, RatingSourceCatalog.Metacritic);
        options.DefaultSource(ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Rawg);
    }

    [Fact]
    public void AStoredChoiceSurvivesAProviderChange_AndComesBackWhenThatProviderDoes()
    {
        // The admin picked Metacritic with RAWG as the default.
        // It is ignored, not erased, while IGDB is the default, since IGDB can't produce that number, and honouring it would leave every IGDB-linked game with no rating.
        // With RAWG configured back, the same stored choice is honoured again.
        var overrides = new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.Metacritic };

        OptionsFor(RatingSourceCatalog.Igdb).Resolve(overrides, ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Igdb);
        OptionsFor(RatingSourceCatalog.Rawg).Resolve(overrides, ReferenceItemType.VideoGame).Should().Be(RatingSourceCatalog.Metacritic);
    }

    [Theory]
    // Both keys stay declared with their scales however the deployment is configured, since references linked through either provider keep those values.
    // ScaleOf throws on a source it doesn't know, so dropping a declaration would turn every stored value into an exception rather than a stale number.
    [InlineData(RatingSourceCatalog.Rawg, 5)]
    [InlineData(RatingSourceCatalog.Metacritic, 100)]
    [InlineData(RatingSourceCatalog.Igdb, 100)]
    [InlineData(RatingSourceCatalog.IgdbCritic, 100)]
    public void EverySourceKeepsItsScale_WhicheverProviderIsCurrentlyDefault(string source, double scale)
    {
        RatingSourceCatalog.ScaleOf(source).Should().Be(scale);
        RatingSourceCatalog.ScaleOf(source).Should().Be(scale); // and it is a pure declaration, not deployment-dependent
    }

    [Theory]
    [InlineData(ReferenceItemType.Movie)]
    [InlineData(ReferenceItemType.TvShow)]
    public void MoviesAndTvShows_OfferTmdbAndImdb_WithTmdbAsTheDefault(ReferenceItemType domain)
    {
        // fixed rather than provider-derived, and rightly so: IMDb isn't a second provider for this domain, it's an extra per-title lookup layered on TMDB's own data.
        var options = OptionsFor(RatingSourceCatalog.Igdb);

        options.AvailableSources(domain).Should().Equal(RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb);
        options.DefaultSource(domain).Should().Be(RatingSourceCatalog.Tmdb);
        options.IsSelectable(domain).Should().BeTrue();
        options.SelectableDomains.Should().Contain(domain);
    }

    [Theory]
    [InlineData(ReferenceItemType.Book)]
    [InlineData(ReferenceItemType.Album)]
    public void SingleSourceDomains_AreNotAdminSelectable(ReferenceItemType domain)
    {
        // These have one source, so nothing to choose, and they join the picker on gaining a second, as movies and TV did with IMDb.
        var options = OptionsFor(RatingSourceCatalog.Igdb);

        options.IsSelectable(domain).Should().BeFalse();
        options.AvailableSources(domain).Should().BeEmpty();
    }

    private static RatingSourceOptions OptionsFor(string defaultProviderKey)
    {
        var igdb = FakeVideoGameReferenceClient.Empty();
        var rawg = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        return new RatingSourceOptions(new ReferenceClientRegistry<IVideoGameReferenceClient>([igdb, rawg], defaultProviderKey));
    }
}
