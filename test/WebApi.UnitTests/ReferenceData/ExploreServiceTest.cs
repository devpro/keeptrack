using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The Explore read path, which pages a stored provider ranking rather than calling a provider: exclusions,
/// the rank cursor, and which stored ordering/rating a domain's admin setting selects. The catalogue mock
/// honours the cursor exactly as the repository does, so the paging assertions here are about real behaviour
/// and not about a stub returning a fixed list.
/// </summary>
[Trait("Category", "UnitTests")]
public class ExploreServiceTest
{
    private readonly Mock<IAppSettingRepository> _appSettingRepository = new();
    private readonly Mock<IExploreCatalogueRepository> _catalogueRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IVideoGameRepository> _videoGameRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IVideoGameReferenceRepository> _videoGameReferenceRepository = new();
    private readonly Mock<IExploreDismissalRepository> _dismissalRepository = new();

    private ExploreService CreateService()
    {
        // no admin override by default => the code default source per domain (tmdb / rawg) is used
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string>());
        return new(
            _appSettingRepository.Object, _catalogueRepository.Object,
            _movieRepository.Object, _tvShowRepository.Object, _videoGameRepository.Object,
            _movieReferenceRepository.Object, _tvShowReferenceRepository.Object, _videoGameReferenceRepository.Object,
            _dismissalRepository.Object);
    }

    private static ExploreCatalogueEntryModel Entry(ExploreItemType type, string ranking, string externalId, int rank, params (string Source, double Value)[] ratings) =>
        new()
        {
            ItemType = type,
            Ranking = ranking,
            ExternalId = externalId,
            Rank = rank,
            Title = $"Title {externalId}",
            Year = 2000,
            Ratings = ratings.ToDictionary(r => r.Source, r => r.Value)
        };

    /// <summary>
    /// Stands the stored ranking up behind the repository mock, honouring the rank cursor and page size the
    /// service asks with - so a test can assert that paging continues from the right place rather than merely
    /// that a call was made.
    /// </summary>
    private void Catalogue(ExploreItemType type, string ranking, params ExploreCatalogueEntryModel[] entries)
    {
        _catalogueRepository
            .Setup(r => r.FindRankedAsync(type, ranking, It.IsAny<int>(), It.IsAny<int>()))
            .ReturnsAsync((ExploreItemType _, string _, int afterRank, int take) =>
                entries.Where(e => e.Rank > afterRank).OrderBy(e => e.Rank).Take(take).ToList());
        _catalogueRepository.Setup(r => r.CountAsync(type, ranking)).ReturnsAsync(entries.Length);
    }

    // "this owner tracks nothing and has dismissed nothing" - the starting point of every test that isn't
    // specifically about the exclusion set.
    private void NoExclusions(ExploreItemType type)
    {
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", type, It.IsAny<string>())).ReturnsAsync([]);
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _videoGameRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync([]);
        _movieRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _tvShowRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _videoGameRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([]);
        _movieReferenceRepository.Setup(r => r.FindExternalIdsAsync(It.IsAny<IReadOnlyCollection<string>>(), It.IsAny<string>())).ReturnsAsync([]);
        _tvShowReferenceRepository.Setup(r => r.FindExternalIdsAsync(It.IsAny<IReadOnlyCollection<string>>(), It.IsAny<string>())).ReturnsAsync([]);
        _videoGameReferenceRepository.Setup(r => r.FindExternalIdsAsync(It.IsAny<IReadOnlyCollection<string>>(), It.IsAny<string>())).ReturnsAsync([]);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ExcludesTitlesTheOwnerTracksOrHasDismissed_AndMapsTheRating()
    {
        NoExclusions(ExploreItemType.Movie);
        // owner tracks reference "ref-a", whose TMDB id is "100"
        _movieRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync(["ref-a"]);
        _movieReferenceRepository.Setup(r => r.FindExternalIdsAsync(It.Is<IReadOnlyCollection<string>>(c => c.Contains("ref-a")), "tmdb"))
            .ReturnsAsync(["100"]);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie, "tmdb")).ReturnsAsync(["200"]);
        Catalogue(ExploreItemType.Movie, "tmdb",
            Entry(ExploreItemType.Movie, "tmdb", "100", 1, ("tmdb", 9.0)),
            Entry(ExploreItemType.Movie, "tmdb", "200", 2, ("tmdb", 8.8)),
            Entry(ExploreItemType.Movie, "tmdb", "300", 3, ("tmdb", 8.6)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        // 100 is tracked, 200 is dismissed - only 300 survives
        page.Items.Should().ContainSingle();
        page.Items[0].ExternalId.Should().Be("300");
        page.Items[0].Rating.Should().Be(8.6);
        page.Items[0].RatingScale.Should().Be(10);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ExcludesATitleTheOwnerTracks_EvenWhenItHasNoReferenceLink()
    {
        NoExclusions(ExploreItemType.Movie);
        // an item the owner typed in or imported that never got linked has no provider id to exclude by -
        // only its title. Matching goes through the app-wide TitleNormalizer, so it is exactly as forgiving
        // as every other title match in the codebase (case and surrounding whitespace), no more.
        _movieRepository.Setup(r => r.FindDistinctTitlesAsync("owner")).ReturnsAsync([" tITLE 1 "]);
        Catalogue(ExploreItemType.Movie, "tmdb",
            Entry(ExploreItemType.Movie, "tmdb", "1", 1, ("tmdb", 8.7)),
            Entry(ExploreItemType.Movie, "tmdb", "2", 2, ("tmdb", 8.6)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.ExternalId.Should().Be("2");
    }

    [Fact]
    public async Task GetSuggestionsAsync_StopsAtTheRequestedCount_AndReportsACursorToContinueFrom()
    {
        NoExclusions(ExploreItemType.Movie);
        Catalogue(ExploreItemType.Movie, "tmdb",
            [.. Enumerable.Range(1, 10).Select(i => Entry(ExploreItemType.Movie, "tmdb", $"m{i}", i, ("tmdb", 9.0)))]);

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 3, null, TestContext.Current.CancellationToken);

        page.Items.Select(s => s.ExternalId).Should().Equal(["m1", "m2", "m3"]);
        page.NextCursor.Should().Be(3, "the cursor is the rank of the last entry examined");
    }

    [Fact]
    public async Task GetSuggestionsAsync_ContinuesFromTheCursor_WithoutRepeatingOrSkipping()
    {
        NoExclusions(ExploreItemType.Movie);
        Catalogue(ExploreItemType.Movie, "tmdb",
            [.. Enumerable.Range(1, 10).Select(i => Entry(ExploreItemType.Movie, "tmdb", $"m{i}", i, ("tmdb", 9.0)))]);
        var service = CreateService();

        var first = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 4, null, TestContext.Current.CancellationToken);
        var second = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 4, first.NextCursor, TestContext.Current.CancellationToken);

        first.Items.Select(s => s.ExternalId).Should().Equal(["m1", "m2", "m3", "m4"]);
        second.Items.Select(s => s.ExternalId).Should().Equal(["m5", "m6", "m7", "m8"]);
    }

    [Fact]
    public async Task GetSuggestionsAsync_AdvancesTheCursorPastExcludedEntries_SoTheyAreNeverReExamined()
    {
        NoExclusions(ExploreItemType.Movie);
        // the whole tail after the single survivor is dismissed: the cursor must still reach the end of it,
        // or the next page would re-read and re-filter the same run of titles forever.
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie, "tmdb"))
            .ReturnsAsync(["m2", "m3", "m4"]);
        Catalogue(ExploreItemType.Movie, "tmdb",
            [.. Enumerable.Range(1, 4).Select(i => Entry(ExploreItemType.Movie, "tmdb", $"m{i}", i, ("tmdb", 9.0)))]);

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.ExternalId.Should().Be("m1");
        page.NextCursor.Should().BeNull("the ranking ran out, so there is nothing to continue from");
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenTheRankingIsExhausted_ReportsNoCursor()
    {
        NoExclusions(ExploreItemType.Movie);
        Catalogue(ExploreItemType.Movie, "tmdb", Entry(ExploreItemType.Movie, "tmdb", "m1", 1, ("tmdb", 9.0)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle();
        page.NextCursor.Should().BeNull();
        page.CataloguePending.Should().BeFalse();
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenTheRankingHasNotBeenBuiltYet_SaysSo()
    {
        NoExclusions(ExploreItemType.Movie);
        Catalogue(ExploreItemType.Movie, "tmdb");

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        // "not built yet" (a fresh deployment before the first refresh pass) is an empty list too, but it
        // means the opposite of "you've seen everything" to a user.
        page.Items.Should().BeEmpty();
        page.CataloguePending.Should().BeTrue();
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenTheOwnerTracksEverythingInTheRanking_IsNotReportedAsPending()
    {
        NoExclusions(ExploreItemType.Movie);
        _dismissalRepository.Setup(r => r.FindDismissedExternalIdsAsync("owner", ExploreItemType.Movie, "tmdb")).ReturnsAsync(["m1"]);
        Catalogue(ExploreItemType.Movie, "tmdb", Entry(ExploreItemType.Movie, "tmdb", "m1", 1, ("tmdb", 9.0)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().BeEmpty();
        page.CataloguePending.Should().BeFalse("the catalogue is built - this owner has simply run out of new titles");
    }

    [Fact]
    public async Task GetSuggestionsAsync_UsesTheTvShowRankingAndRepositories_ForTheTvShowDomain()
    {
        NoExclusions(ExploreItemType.TvShow);
        Catalogue(ExploreItemType.TvShow, "tmdb", Entry(ExploreItemType.TvShow, "tmdb", "tv1", 1, ("tmdb", 9.4)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.TvShow, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.ExternalId.Should().Be("tv1");
        _catalogueRepository.Verify(
            r => r.FindRankedAsync(ExploreItemType.Movie, It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenImdbIsThePrimarySource_ShowsTheStoredImdbRating_KeepingTheTmdbOrdering()
    {
        var service = CreateService();
        // admin picked IMDb as the movie primary source
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        NoExclusions(ExploreItemType.Movie);
        // IMDb has no catalogue API, so there is no "imdb" ordering at all - the entries are ranked by TMDB
        // and simply carry both numbers.
        Catalogue(ExploreItemType.Movie, "tmdb",
            Entry(ExploreItemType.Movie, "tmdb", "20", 1, ("tmdb", 9.0), ("imdb", 7.0)),
            Entry(ExploreItemType.Movie, "tmdb", "10", 2, ("tmdb", 5.0), ("imdb", 8.5)));

        var page = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        // the shown value is IMDb's, but the ORDER stays TMDB's (no re-rank from partial IMDb coverage)
        page.Items.Select(s => s.ExternalId).Should().Equal(["20", "10"]);
        page.Items[0].Rating.Should().Be(7.0);
        page.Items[1].Rating.Should().Be(8.5);
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenImdbIsSelectedButAnEntryHasNoImdbRatingYet_ShowsNoRating()
    {
        var service = CreateService();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        NoExclusions(ExploreItemType.Movie);
        // the IMDb backfill is bounded per pass, so an entry deep in the ranking can legitimately not have one
        // yet. Showing its TMDB number under an IMDb selection would be a quietly wrong number; showing none
        // is the same thing the per-request OMDb lookup used to do when it came back empty.
        Catalogue(ExploreItemType.Movie, "tmdb", Entry(ExploreItemType.Movie, "tmdb", "20", 1, ("tmdb", 9.0)));

        var page = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle();
        page.Items[0].Rating.Should().BeNull();
        page.Items[0].RatingScale.Should().BeNull();
    }

    [Fact]
    public async Task GetSuggestionsAsync_WhenExploreIsForcedToTmdb_ShowsTheTmdbRatingDespiteTheImdbPrimarySource()
    {
        var service = CreateService();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _appSettingRepository.Setup(r => r.GetExploreUseTmdbAsync()).ReturnsAsync(true);
        NoExclusions(ExploreItemType.Movie);
        Catalogue(ExploreItemType.Movie, "tmdb",
            Entry(ExploreItemType.Movie, "tmdb", "20", 1, ("tmdb", 9.0), ("imdb", 7.0)));

        var page = await service.GetSuggestionsAsync(ExploreItemType.Movie, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.Rating.Should().Be(9.0);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_ReadsTheRawgOrderedRanking_ByDefault()
    {
        NoExclusions(ExploreItemType.VideoGame);
        Catalogue(ExploreItemType.VideoGame, "rawg",
            Entry(ExploreItemType.VideoGame, "rawg", "g1", 1, ("rawg", 4.7), ("metacritic", 96)),
            Entry(ExploreItemType.VideoGame, "rawg", "g2", 2, ("rawg", 4.5), ("metacritic", 92)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Select(s => s.ExternalId).Should().Equal(["g1", "g2"]);
        // RAWG's own score on its own 0-5 scale
        page.Items[0].Rating.Should().Be(4.7);
        page.Items[0].RatingScale.Should().Be(5);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_WhenMetacriticIsThePrimarySource_ReadsTheMetacriticOrderedRanking()
    {
        var service = CreateService();
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync()).ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = "metacritic" });
        NoExclusions(ExploreItemType.VideoGame);
        // unlike TMDB, RAWG genuinely sorts differently per source, so each source is a separately stored
        // ordering - reading the wrong one would show the right numbers in the wrong order.
        Catalogue(ExploreItemType.VideoGame, "metacritic",
            Entry(ExploreItemType.VideoGame, "metacritic", "g9", 1, ("rawg", 4.1), ("metacritic", 98)));

        var page = await service.GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.ExternalId.Should().Be("g9");
        page.Items[0].Rating.Should().Be(98);
        page.Items[0].RatingScale.Should().Be(100);
        _catalogueRepository.Verify(
            r => r.FindRankedAsync(ExploreItemType.VideoGame, "rawg", It.IsAny<int>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_IsUnaffectedByTheForceTmdbExploreFlag()
    {
        var service = CreateService();
        // the flag exists only to keep movie/TV discovery off the IMDb backfill - "tmdb" is not a video game
        // rating source at all, so it must never leak into this domain's ranking.
        _appSettingRepository.Setup(r => r.GetExploreUseTmdbAsync()).ReturnsAsync(true);
        NoExclusions(ExploreItemType.VideoGame);
        Catalogue(ExploreItemType.VideoGame, "rawg", Entry(ExploreItemType.VideoGame, "rawg", "g1", 1, ("rawg", 4.7)));

        var page = await service.GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.RatingScale.Should().Be(5);
    }

    [Fact]
    public async Task GetSuggestionsAsync_ForVideoGames_ExcludesGamesTheOwnerAlreadyTracks()
    {
        NoExclusions(ExploreItemType.VideoGame);
        _videoGameRepository.Setup(r => r.FindLinkedReferenceIdsAsync("owner")).ReturnsAsync(["ref-g"]);
        // the tracked game's reference is read in the RAWG number space - never a TMDB one
        _videoGameReferenceRepository.Setup(r => r.FindExternalIdsAsync(It.Is<IReadOnlyCollection<string>>(c => c.Contains("ref-g")), "rawg"))
            .ReturnsAsync(["g1"]);
        Catalogue(ExploreItemType.VideoGame, "rawg",
            Entry(ExploreItemType.VideoGame, "rawg", "g1", 1, ("rawg", 4.7)),
            Entry(ExploreItemType.VideoGame, "rawg", "g2", 2, ("rawg", 4.5)));

        var page = await CreateService().GetSuggestionsAsync(ExploreItemType.VideoGame, "owner", 24, null, TestContext.Current.CancellationToken);

        page.Items.Should().ContainSingle().Which.ExternalId.Should().Be("g2");
    }

    [Fact]
    public async Task DismissAsync_RecordsADismissalKeyedByTheDomainsDiscoveryProvider()
    {
        var service = CreateService();

        await service.DismissAsync(ExploreItemType.TvShow, "owner", "tv9");
        await service.DismissAsync(ExploreItemType.VideoGame, "owner", "g9");

        _dismissalRepository.Verify(r => r.AddAsync(It.Is<ExploreDismissalModel>(m =>
            m.OwnerId == "owner" && m.ItemType == ExploreItemType.TvShow && m.ExternalSource == "tmdb" && m.ExternalId == "tv9")), Times.Once);
        // a RAWG id and a TMDB id are both plain integers, so the provider is stored, never inferred
        _dismissalRepository.Verify(r => r.AddAsync(It.Is<ExploreDismissalModel>(m =>
            m.OwnerId == "owner" && m.ItemType == ExploreItemType.VideoGame && m.ExternalSource == "rawg" && m.ExternalId == "g9")), Times.Once);
    }

    [Fact]
    public async Task UndismissAsync_RemovesTheDismissal()
    {
        await CreateService().UndismissAsync(ExploreItemType.Movie, "owner", "42");

        _dismissalRepository.Verify(r => r.RemoveAsync("owner", ExploreItemType.Movie, "tmdb", "42"), Times.Once);
    }
}
