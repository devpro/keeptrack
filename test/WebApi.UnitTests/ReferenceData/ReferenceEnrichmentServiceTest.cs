using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

// the recompute's bulk re-stamp payload; aliased so those tests read as assertions rather than as type noise
using RatingUpdateBatch = System.Collections.Generic.IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)>;
using ReferenceRatingsPage = System.Collections.Generic.IReadOnlyList<(string Id, System.Collections.Generic.Dictionary<string, Keeptrack.Domain.Models.ReferenceRatingModel> Ratings)>;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class ReferenceEnrichmentServiceTest
{
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();
    private readonly Mock<IMovieReferenceRepository> _movieReferenceRepository = new();
    private readonly Mock<IPersonReferenceRepository> _personReferenceRepository = new();
    private readonly Mock<IBookReferenceRepository> _bookReferenceRepository = new();
    private readonly Mock<IVideoGameReferenceRepository> _videoGameReferenceRepository = new();
    private readonly Mock<IAlbumReferenceRepository> _albumReferenceRepository = new();
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IMovieRepository> _movieRepository = new();
    private readonly Mock<IBookRepository> _bookRepository = new();
    private readonly Mock<IVideoGameRepository> _videoGameRepository = new();
    private readonly Mock<IAlbumRepository> _albumRepository = new();
    private readonly Mock<IAppSettingRepository> _appSettingRepository = new();
    private readonly FakeBookRatingByIsbnLookup _bookRatingByIsbnLookup = new();

    public ReferenceEnrichmentServiceTest()
    {
        // default: no admin override, so every domain resolves to its code default (see RatingSourceCatalog).
        // individual tests override this to exercise a stored primary-source choice.
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string>());

        // default: recompute has something to do. The action early-outs when every linked item is already on
        // the selected source, so a test about what recompute *writes* has to say that isn't the case here;
        // RecomputeReferenceRatingsAsync_DoesNothing_WhenEveryItemIsAlreadyOnTheSelectedSource covers the other side.
        _movieRepository.Setup(r => r.CountLinkedOnOtherRatingSourceAsync(It.IsAny<string>())).ReturnsAsync(1);
        _tvShowRepository.Setup(r => r.CountLinkedOnOtherRatingSourceAsync(It.IsAny<string>())).ReturnsAsync(1);
        _videoGameRepository.Setup(r => r.CountLinkedOnOtherRatingSourceAsync(It.IsAny<string>())).ReturnsAsync(1);

        // the real OmdbClient spends from the shared allowance and writes the day off on OMDb's "limit
        // reached" 401; the fakes only model that when they share a budget, so hand it the same one the
        // service reads (see FakeOmdbClient.ReportsLimitReached).
        _omdbClient.Budget = _omdbCallBudget;
    }

    /// <summary>
    /// The registry always has "openlibrary" as the deployment default - matches FakeBookReferenceClient's
    /// hardcoded ProviderKey, so every existing test that never mentions a provider keeps resolving the
    /// same fake it always did.
    /// </summary>
    private const string DefaultBookProvider = "openlibrary";

    private readonly FakeOmdbClient _omdbClient = FakeOmdbClient.Empty();

    private readonly FakeOmdbCallBudget _omdbCallBudget = new();

    private ReferenceEnrichmentService CreateService(
        FakeTmdbClient tmdbClient,
        FakeBookReferenceClient? bookReferenceClient = null,
        FakeVideoGameReferenceClient? videoGameClient = null,
        FakeDiscogsClient? discogsClient = null,
        FakeBnfClient? bnfClient = null,
        FakeVideoGameReferenceClient? secondaryVideoGameClient = null) => new(
        tmdbClient,
        _omdbClient,
        _omdbCallBudget,
        new ReferenceClientRegistry<IBookReferenceClient>([bookReferenceClient ?? FakeBookReferenceClient.Empty(), bnfClient ?? FakeBnfClient.Empty()], DefaultBookProvider),
        _bookRatingByIsbnLookup,
        VideoGameRegistry(videoGameClient, secondaryVideoGameClient), discogsClient ?? FakeDiscogsClient.Empty(),
        _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
        _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
        _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object,
        _appSettingRepository.Object, new RatingSourceOptions(VideoGameRegistry(videoGameClient, secondaryVideoGameClient)),
        NullLogger<ReferenceEnrichmentService>.Instance);

    /// <summary>
    /// The video game registry a test runs against. The first client is always the deployment default (the
    /// registry resolves a null key to it), so a test that needs the secondary provider to be the default
    /// simply passes it as the primary - which is what the RAWG-era cases below do.
    /// </summary>
    private static ReferenceClientRegistry<IVideoGameReferenceClient> VideoGameRegistry(
        FakeVideoGameReferenceClient? primary, FakeVideoGameReferenceClient? secondary)
    {
        var main = primary ?? FakeVideoGameReferenceClient.Empty();
        List<IVideoGameReferenceClient> clients = secondary is null ? [main] : [main, secondary];
        return new ReferenceClientRegistry<IVideoGameReferenceClient>(clients, main.ProviderKey);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchReturnsNoResults()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(
            new TmdbSearchResult("1", "Some Show", 2020, null, null),
            new TmdbSearchResult("2", "Some Show", 2020, null, null)));

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults(new TmdbSearchResult("42", "Some Show", 2020, "Synopsis", null));
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) =>
            {
                m.Id ??= "generated-id";
                return m;
            });
        var service = CreateService(tmdbClient);

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.ExternalIds["tmdb"] == "42")), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, It.IsAny<string>(), "Some Show", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PropagatesTheUpsertedReferenceId()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) =>
            {
                m.Id = "reference-1";
                return m;
            });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        result.Id.Should().Be("reference-1");
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, "reference-1", "Some Show", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_ReusesTheSameReferenceByTmdbId_EvenWhenTitleTextDiffersEntirely()
    {
        // regression test: resolving the exact same TMDB show twice under two completely unrelated title
        // strings (e.g. a translation an admin didn't recognize) used to create a second, duplicate
        // reference document, because the "does this already exist" check only ever looked at title/year -
        // tmdbId is now checked first and is authoritative.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByExternalIdAsync("tmdb", "42"))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1",
                Title = "The Wire",
                TitleNormalized = "the wire",
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
                MatchedAliases = [new ReferenceMatchModel { Title = "the wire", Year = 2002 }]
            });
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Totally Unrelated Search Text", null, "42");

        result.Id.Should().Be("reference-1");
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.Id == "reference-1")), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_RecordsBothTheSearchedAndCanonicalTitleAsMatchedAliases()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) =>
            {
                m.Id ??= "reference-1";
                return m;
            });
        var service = CreateService(tmdbClient);

        // the tenant searched with a different-language title than TMDB's canonical English one
        await service.ResolveTvShowAsync("Le Fil", 2002, "42");

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.MatchedAliases.Any(a => a.Title == "the wire" && a.Year == 2002)
                                                                                              && m.MatchedAliases.Any(a => a.Title == "le fil" && a.Year == 2002))), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PreservesPreviouslyKnownMatchedAliases_WhenReResolvingAnExistingReference()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "The Wire", 2002, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Le Fil", 2002))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1",
                Title = "The Wire",
                TitleNormalized = "the wire",
                ExternalIds = [],
                MatchedAliases = [new ReferenceMatchModel { Title = "the wire", Year = 2002 }, new ReferenceMatchModel { Title = "il filo", Year = 2001 }]
            });
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        await service.ResolveTvShowAsync("Le Fil", 2002, "42");

        // an alias contributed by a third tenant earlier (il filo) must survive a later re-resolution
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.MatchedAliases.Any(a => a.Title == "the wire" && a.Year == 2002)
                                                                                              && m.MatchedAliases.Any(a => a.Title == "il filo" && a.Year == 2001)
                                                                                              && m.MatchedAliases.Any(a => a.Title == "le fil" && a.Year == 2002))), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_ReusesExistingPersonReference_ForAnAlreadyKnownActor()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        tmdbClient.Cast["42"] = [new TmdbCastMember("99", "Actor Name", "A Character", 0, null)];

        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) =>
            {
                m.Id ??= "reference-1";
                return m;
            });
        _personReferenceRepository
            .Setup(r => r.FindByExternalIdAsync("tmdb", "99"))
            .ReturnsAsync(new PersonReferenceModel { Id = "person-1", Name = "Actor Name", ExternalIds = new Dictionary<string, string> { ["tmdb"] = "99" } });
        _personReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>()))
            .ReturnsAsync((PersonReferenceModel m) => m);

        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        // the same actor already known from a previous resolution must be reused, not duplicated
        _personReferenceRepository.Verify(r => r.UpsertAsync(It.Is<PersonReferenceModel>(m => m.Id == "person-1")), Times.Once);
        result.Cast.Should().ContainSingle(c => c.PersonReferenceId == "person-1" && c.CharacterName == "A Character");
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_RelinksToTheNewMatch_WhenTitleWasEditedAwayFromTheCurrentLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel
        {
            Id = "show-1",
            OwnerId = "owner",
            Title = "A Different Show",
            Year = 2021,
            ReferenceId = "old-reference"
        };
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("A Different Show", 2021))
            .ReturnsAsync(new TvShowReferenceModel { Id = "new-reference", Title = "A Different Show", TitleNormalized = "a different show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("new-reference");
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == "new-reference"), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel
        {
            Id = "show-1",
            OwnerId = "owner",
            Title = "Some Show",
            Year = 2020,
            ReferenceId = "old-reference"
        };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 2020)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository.Setup(r => r.FindByTitleAsync("Some Show")).ReturnsAsync((TvShowReferenceModel?)null);

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        // no match for the current title means the previously stored link no longer corresponds to what
        // the tenant just told us is correct - clear it (which also puts it back in the admin's unresolved queue)
        result.ReferenceId.Should().BeEmpty();
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_FallsBackToTitleOnlyMatch_WhenTheTenantHasNoYearSet()
    {
        // regression test: the title-only fallback used to be skipped whenever Year was null, which meant
        // any linked show with no recorded year would unlink itself on every refresh, since the title+year
        // query can never succeed with a null year against a reference that has a real one.
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel
        {
            Id = "show-1",
            OwnerId = "owner",
            Title = "Some Show",
            Year = null,
            ReferenceId = "reference-1"
        };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", null)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Some Show"))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1",
                Title = "Some Show",
                TitleNormalized = "some show",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_LinksAndUpdatesTitle_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Typo'd Show", Year = 2020 };
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Show", 2020))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Show");
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Show", 2020, "reference-1", "Some Show", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        // the tenant's own recorded year is pre-populated with the reference's canonical year on link -
        // still freely editable afterward, but starts from a trustworthy value instead of the tenant's guess
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 2019 };
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Show", 2019))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-1",
                Title = "Some Show",
                TitleNormalized = "some show",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.Year.Should().Be(2020);
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.Year == 2020), "owner"), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2019, "reference-1", "Some Show", 2020, It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_DoesNotFallBackToTitleOnlyMatch_WhenTenantHasAYearButTitleYearMatchMisses()
    {
        // regression test: a title-only fallback that ignores a tenant-recorded year risks matching a
        // same-titled but genuinely different reference (e.g. "Road House" 1990 vs. 2024) - once the 2024
        // remake is linked, checking for a match on the 1990 original must not silently attach it to the
        // 2024 reference just because no (title, 1990) alias has been confirmed yet.
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Road House", Year = 1990 };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Road House", 1990)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Road House"))
            .ReturnsAsync(new TvShowReferenceModel
            {
                Id = "reference-2024",
                Title = "Road House",
                TitleNormalized = "road house",
                Year = 2024,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().BeNullOrEmpty();
        _tvShowReferenceRepository.Verify(r => r.FindByTitleAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_ReturnsUnchanged_WhenNoMatchFound()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 2020 };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 2020)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository.Setup(r => r.FindByTitleAsync("Some Show")).ReturnsAsync((TvShowReferenceModel?)null);

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        // was never linked and still isn't - nothing to clear, so no write should happen at all
        result.ReferenceId.Should().BeNullOrEmpty();
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_LinksAndUpdatesTitle_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Typo'd Movie", Year = 2020 };
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Movie", 2020))
            .ReturnsAsync(new MovieReferenceModel { Id = "reference-1", Title = "Some Movie", TitleNormalized = "some movie", ExternalIds = [] });

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Movie");
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Movie", Year = 2019 };
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Movie", 2019))
            .ReturnsAsync(new MovieReferenceModel
            {
                Id = "reference-1",
                Title = "Some Movie",
                TitleNormalized = "some movie",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.Year.Should().Be(2020);
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.Year == 2020), "owner"), Times.Once);
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2019, "reference-1", "Some Movie", 2020, It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel
        {
            Id = "movie-1",
            OwnerId = "owner",
            Title = "Some Movie",
            Year = 2020,
            ReferenceId = "old-reference"
        };
        _movieReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Movie", 2020)).ReturnsAsync((MovieReferenceModel?)null);
        _movieReferenceRepository.Setup(r => r.FindByTitleAsync("Some Movie")).ReturnsAsync((MovieReferenceModel?)null);

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_DoesNotFallBackToTitleOnlyMatch_WhenTenantHasAYearButTitleYearMatchMisses()
    {
        // same regression as the TvShow test above, for the Movie path - see that test's own comment
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Road House", Year = 1990 };
        _movieReferenceRepository.Setup(r => r.FindByTitleYearAsync("Road House", 1990)).ReturnsAsync((MovieReferenceModel?)null);
        _movieReferenceRepository
            .Setup(r => r.FindByTitleAsync("Road House"))
            .ReturnsAsync(new MovieReferenceModel
            {
                Id = "reference-2024",
                Title = "Road House",
                TitleNormalized = "road house",
                Year = 2024,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().BeNullOrEmpty();
        _movieReferenceRepository.Verify(r => r.FindByTitleAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task ResolveMovieAsync_DoesNotMergeIntoAnUnrelatedSameTitledReference_WhenResolvingADifferentTmdbIdWithItsOwnKnownYear()
    {
        // regression test for the real bug report: linking "Road House" (2024, tmdbId "2024id") first, then
        // resolving "Road House" (1990, tmdbId "1990id") separately, used to look up the existing reference
        // by title only once the (title, 1990) alias came up empty - finding the 2024 document and reusing
        // its Id for the upsert, which doesn't just link wrong, it overwrites the 2024 reference's own data
        // with the 1990 movie's data (a de-facto merge of two distinct real movies into one document).
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["1990id"] = new TmdbMovieDetails("1990id", "Road House", 1990, "1989 original synopsis", [], null, null, null);
        _movieReferenceRepository
            .Setup(r => r.FindByExternalIdAsync("tmdb", "1990id"))
            .ReturnsAsync((MovieReferenceModel?)null);
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Road House", 1990))
            .ReturnsAsync((MovieReferenceModel?)null);
        // the 2024 remake was already resolved and is the only thing a title-only lookup would find
        _movieReferenceRepository
            .Setup(r => r.FindByTitleAsync("Road House"))
            .ReturnsAsync(new MovieReferenceModel
            {
                Id = "reference-2024",
                Title = "Road House",
                TitleNormalized = "road house",
                Year = 2024,
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "2024id" }
            });
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) =>
        {
            m.Id ??= "reference-1990";
            return m;
        });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Road House", 1990, "1990id");

        result.Id.Should().NotBe("reference-2024");
        _movieReferenceRepository.Verify(r => r.FindByTitleAsync(It.IsAny<string>()), Times.Never);
        _movieReferenceRepository.Verify(r => r.UpsertAsync(It.Is<MovieReferenceModel>(m => m.Id != "reference-2024")), Times.Once);
    }

    [Fact]
    public async Task ResolveMovieAsync_StoresTheTmdbRating_AndPropagatesThePrimaryScalar()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.8, 1234);
        _movieReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .ReturnsAsync((MovieReferenceModel m) =>
            {
                m.Id = "reference-1";
                return m;
            });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Some Movie", 2020, "42");

        result.Ratings.Should().ContainKey("tmdb");
        result.Ratings["tmdb"].Value.Should().Be(7.8);
        result.Ratings["tmdb"].Scale.Should().Be(10);
        result.Ratings["tmdb"].Count.Should().Be(1234);
        // the primary source's value/scale is denormalized onto every matching tenant movie
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), 7.8, 10, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveMovieAsync_StoresNoRating_WhenTmdbHasNoVotes()
    {
        // TMDB returns vote_average 0 / vote_count 0 for an unrated title - that must not be stored as a real 0
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 0, 0);
        _movieReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .ReturnsAsync((MovieReferenceModel m) =>
            {
                m.Id = "reference-1";
                return m;
            });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Some Movie", 2020, "42");

        result.Ratings.Should().BeEmpty();
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), null, null, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_ForcesAFullFetch_WhenReferenceHasNoRatingsYet_EvenIfTmdbReportsNoChange()
    {
        // an already-linked reference created before ratings existed must backfill a rating on the next sync,
        // so the cheap "nothing changed" short-circuit must not fire while Ratings is still empty
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 6.5, 500);
        _movieReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .ReturnsAsync((MovieReferenceModel m) =>
            {
                m.Id = "reference-1";
                return m;
            });
        var reference = new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5)
        };
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        tmdbClient.MovieDetailsRequested.Should().Contain("42");
        result.Ratings["tmdb"].Value.Should().Be(6.5);
        // and the refreshed rating is re-propagated to every already-linked tenant movie
        _movieRepository.Verify(r => r.SetReferenceRatingAsync("reference-1", 6.5, 10, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_TakesTheNoChangeShortCircuit_WhenAlreadyRated()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _movieReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .ReturnsAsync((MovieReferenceModel m) => m);
        var reference = new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5),
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 6.5, Scale = 10, Count = 500 } }
        };
        var service = CreateService(tmdbClient);

        var (_, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        tmdbClient.MovieDetailsRequested.Should().NotContain("42");
        _movieRepository.Verify(r => r.SetReferenceRatingAsync(It.IsAny<string>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_SetsTheDenormalizedRating_FromTheMatchedReference()
    {
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Movie", 2020))
            .ReturnsAsync(new MovieReferenceModel
            {
                Id = "reference-1",
                Title = "Some Movie",
                TitleNormalized = "some movie",
                Year = 2020,
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
                Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 8.1, Scale = 10, Count = 900 } }
            });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner-1", Title = "Some Movie", Year = 2020 };

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceRating.Should().Be(8.1);
        result.ReferenceRatingScale.Should().Be(10);
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceRating == 8.1 && m.ReferenceRatingScale == 10), "owner-1"), Times.Once);
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), 8.1, 10, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveMovieAsync_AddsTheImdbRating_AndStoresTheImdbIdInExternalIds()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.8, 1234, "tt0042");
        _omdbClient.Ratings["tt0042"] = new OmdbRating(8.9, 500_000);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Some Movie", 2020, "42");

        // both sources land in the reference dict, each on its own scale
        result.Ratings["tmdb"].Value.Should().Be(7.8);
        result.Ratings["imdb"].Value.Should().Be(8.9);
        result.Ratings["imdb"].Scale.Should().Be(10);
        result.Ratings["imdb"].Count.Should().Be(500_000);
        // the imdb id is stored so a later sync can backfill/refresh it cheaply
        result.ExternalIds["imdb"].Should().Be("tt0042");
        // tmdb is the default primary, so the denormalized scalar is still tmdb's
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), 7.8, 10, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveMovieAsync_StoresTheImdbId_EvenWhenOmdbHasNoRatingYet()
    {
        // no OMDb rating (unknown title, or no OMDb key) must still record the imdb id, so the periodic
        // sync's cheap backfill has a key to retry with instead of the id being lost forever
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.8, 1234, "tt0042");
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Some Movie", 2020, "42");

        result.Ratings.Should().NotContainKey("imdb");
        result.ExternalIds["imdb"].Should().Be("tt0042");
    }

    [Fact]
    public async Task ResolveMovieAsync_DenormalizesTheImdbScore_WhenImdbIsTheAdminSelectedPrimarySource()
    {
        // the admin-selectable primary source (same mechanism as video games' RAWG/Metacritic) drives the
        // list pill / Ref-sort scalar: with imdb selected for movies, imdb's value/scale is denormalized
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.8, 1234, "tt0042");
        _omdbClient.Ratings["tt0042"] = new OmdbRating(8.9, 500_000);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(tmdbClient);

        await service.ResolveMovieAsync("Some Movie", 2020, "42");

        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>(), 8.9, 10, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_BackfillsImdbCheaply_OnTheNoChangeShortCircuit_WithoutRefetchingDetails()
    {
        // an already-tmdb-rated reference takes the no-change short-circuit, but a missing imdb rating is
        // still backfilled with one cheap OMDb call - never the expensive TMDB details re-fetch
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbClient.Ratings["tt0042"] = new OmdbRating(8.9, 500_000);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42", ["imdb"] = "tt0042" },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5),
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 1234 } }
        };
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Ratings["imdb"].Value.Should().Be(8.9);
        tmdbClient.MovieDetailsRequested.Should().NotContain("42");
        // backfill re-propagates the denormalized scalar to already-linked items
        _movieRepository.Verify(r => r.SetReferenceRatingAsync("reference-1", It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_ResolvesTheImdbIdCheaply_WhenBackfillingAReferenceThatPredatesImdb()
    {
        // the bootstrap case: a reference enriched before IMDb existed has a tmdb rating (so it takes the
        // no-change short-circuit) but NO stored imdb id - the id must be fetched via the cheap external-ids
        // lookup (not a full details re-fetch), stored, and then used to pull the OMDb rating
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        tmdbClient.ImdbIds["42"] = "tt0042";
        _omdbClient.Ratings["tt0042"] = new OmdbRating(8.9, 500_000);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" }, // no imdb id yet
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5),
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 1234 } }
        };
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Ratings["imdb"].Value.Should().Be(8.9);
        // the resolved id is now stored so later syncs skip the external-ids lookup...
        result.ExternalIds["imdb"].Should().Be("tt0042");
        tmdbClient.ImdbIdsRequested.Should().ContainSingle();
        // ...and the expensive full details re-fetch was still avoided
        tmdbClient.MovieDetailsRequested.Should().NotContain("42");
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_DoesNotCallOmdb_OnTheShortCircuit_WhenImdbIsAlreadyPresent()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42", ["imdb"] = "tt0042" },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5),
            Ratings = new Dictionary<string, ReferenceRatingModel>
            {
                ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 1234 },
                ["imdb"] = new() { Value = 8.9, Scale = 10, Count = 500_000 }
            }
        };
        var service = CreateService(tmdbClient);

        var (_, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        _omdbClient.Requested.Should().BeEmpty();
        _movieRepository.Verify(r => r.SetReferenceRatingAsync(It.IsAny<string>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_CallsNoProviderAtAll_OnTheShortCircuit_WhenImdbWasAttemptedRecently()
    {
        // the case this whole stamp exists for: IMDb genuinely has nothing for this title, so no imdb rating
        // will ever appear to short-circuit on. Before the stamp, every pass past the staleness cutoff paid a
        // TMDB external-ids call AND an OMDb call to be told the same thing again, roughly every three days,
        // forever. Both are skipped now - the stamp is checked before the id lookup, not just before OMDb.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        tmdbClient.ImdbIds["42"] = "tt0042";
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: DateTime.UtcNow.AddDays(-10));
        var service = CreateService(tmdbClient);

        var (_, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        _omdbClient.Requested.Should().BeEmpty();
        tmdbClient.ImdbIdsRequested.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_ReAttemptsImdb_WhenTheLastAttemptFellOutOfTheReattemptWindow()
    {
        // the other half: the stamp defers a re-attempt, it doesn't write a title off permanently. A rating
        // that appears on IMDb later is still picked up, one window after the last fruitless ask.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbClient.Ratings["tt0042"] = new OmdbRating(8.9, 500_000);
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: DateTime.UtcNow - RatingSourceCatalog.RatingReattemptAfter.Add(TimeSpan.FromDays(1)));
        reference.ExternalIds["imdb"] = "tt0042";
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Ratings["imdb"].Value.Should().Be(8.9);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_StampsTheAttempt_WhenOmdbAnswersWithNoRating()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.ExternalIds["imdb"] = "tt0042"; // OMDb has no rating seeded for it
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        // "OMDb answered, and has nothing" is a real answer worth remembering - it is what the next pass reads
        changed.Should().BeFalse();
        _omdbClient.Requested.Should().ContainSingle();
        result.RatingsCheckedAt.Should().ContainKey("imdb");
        result.Ratings.Should().NotContainKey("imdb");
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_LeavesNoAttemptStamp_WhenOmdbWasNeverActuallyAsked()
    {
        // no key, a spent budget, a failed request: nothing was learned, so nothing may be recorded. Stamping
        // here would write a title off for the whole window over one bad afternoon.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbClient.Unavailable = true;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.ExternalIds["imdb"] = "tt0042";
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.RatingsCheckedAt.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_LeavesLastEnrichedAtAlone_WhenTheOmdbBudgetIsSpent()
    {
        // Regression, confirmed in the running app: the day after a deploy, 509 of 1516 movie references held
        // an imdb id, no imdb rating and no attempt stamp - the day's OMDb allowance had run out mid-pass. The
        // pass stamped LastEnrichedAt anyway, which marked those documents fresh and dropped them out of
        // FindStaleAsync for a full 3-day staleness window, so half the catalogue showed no rating and no
        // amount of re-running the sync (or the admin recompute, which never calls a provider) moved it.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbCallBudget.Exhausted = true;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.ExternalIds["imdb"] = "tt0042";
        reference.LastEnrichedAt = lastEnrichedAt;
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        // the point: still stale, so the next pass takes it again as soon as the allowance renews
        result.LastEnrichedAt.Should().Be(lastEnrichedAt);
        _omdbClient.Requested.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_LeavesLastEnrichedAtAlone_WhenTheBudgetRunsOutDuringThePass()
    {
        // the pre-call guard can't catch this one: the allowance was open when the call started and OMDb's own
        // "Request limit reached!" 401 is what wrote the day off (another replica having spent the last of it
        // does the same). Re-reading the budget after the lookup is what keeps this document on the queue.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbClient.ReportsLimitReached = true;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.ExternalIds["imdb"] = "tt0042";
        reference.LastEnrichedAt = lastEnrichedAt;
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.LastEnrichedAt.Should().Be(lastEnrichedAt);
        _omdbCallBudget.LimitReported.Should().BeTrue();
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_StampsLastEnrichedAt_WhenOmdbIsUnreachableForAnyOtherReason()
    {
        // The deferral is deliberately narrow: only a spent allowance holds a document at the head of the
        // staleness queue, because only that condition is self-limiting (it renews at UTC midnight). A missing
        // key can never be retried into working, so deferring on it would pin every movie reference at the
        // head forever and starve the rest of the collection - the failure mode
        // RefreshVideoGameReferenceAsync_StampsItAsChecked_WhenNoProviderIdCouldBeResolved exists to prevent.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbClient.Unavailable = true; // no key configured / the request failed - the budget is untouched
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.ExternalIds["imdb"] = "tt0042";
        reference.LastEnrichedAt = lastEnrichedAt;
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.LastEnrichedAt.Should().BeAfter(lastEnrichedAt);
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_StampsLastEnrichedAt_WhenTheBudgetIsSpentButNothingNeededBackfilling()
    {
        // the other half of "narrow": a spent allowance is only a reason to come back if there was actually a
        // call to make. An already-imdb-rated reference wanted nothing from OMDb, so it is fully enriched and
        // must rotate out of the queue like any other.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbCallBudget.Exhausted = true;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.Ratings["imdb"] = new ReferenceRatingModel { Value = 8.9, Scale = 10, Count = 500_000 };
        reference.LastEnrichedAt = lastEnrichedAt;
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.LastEnrichedAt.Should().BeAfter(lastEnrichedAt);
    }

    [Fact]
    public async Task RefreshTvShowReferenceAsync_LeavesLastEnrichedAtAlone_WhenTheOmdbBudgetIsSpent()
    {
        // TV spends from the same daily allowance and syncs first, so it is the domain that empties it - and
        // it carries the same rule, on its own copy of the short-circuit.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        _omdbCallBudget.Exhausted = true;
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = new TvShowReferenceModel
        {
            Id = "reference-1",
            Title = "Some Show",
            TitleNormalized = "some show",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42", ["imdb"] = "tt0042" },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 8.0, Scale = 10, Count = 100 } },
            LastEnrichedAt = lastEnrichedAt
        };
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshTvShowReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.LastEnrichedAt.Should().Be(lastEnrichedAt);
        _omdbClient.Requested.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_KeepsTheKnownImdbRating_WhenAFullFetchCannotReachOmdb()
    {
        // a full fetch rebuilds the ratings map from TMDB, and the imdb value doesn't come from TMDB. With
        // OMDb unreachable, dropping it would discard a rating that cost a call to obtain - and would do so
        // exactly on the days the budget is tight, leaving the cheap backfill to buy it back afterwards.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.9, 2000, "tt0042");
        _omdbClient.Unavailable = true;
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.Ratings["imdb"] = new ReferenceRatingModel { Value = 8.9, Scale = 10, Count = 500_000 };
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.Ratings["tmdb"].Value.Should().Be(7.9); // TMDB's half was refreshed
        result.Ratings["imdb"].Value.Should().Be(8.9); // IMDb's half survived
    }

    [Fact]
    public async Task RefreshMovieReferenceAsync_DropsTheKnownImdbRating_WhenAFullFetchLearnsOmdbNoLongerHasOne()
    {
        // the counterpart: OMDb answering "no rating" is a real answer, so the stale value goes. Only a call
        // that never happened preserves it.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.9, 2000, "tt0042");
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var reference = MovieReferenceAwaitingImdb(attemptedAt: null);
        reference.Ratings["imdb"] = new ReferenceRatingModel { Value = 8.9, Scale = 10, Count = 500_000 };
        var service = CreateService(tmdbClient);

        var (result, _) = await service.RefreshMovieReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.Ratings.Should().NotContainKey("imdb");
        result.RatingsCheckedAt.Should().ContainKey("imdb");
    }

    [Fact]
    public async Task ResolveMovieAsync_CarriesOverTheAttemptStamps_OfTheReferenceItReResolves()
    {
        // a re-resolve rebuilds the document from the provider response; the stamps are memory of what OMDb
        // has already answered, so restarting them would hand the background backfill its old bill back.
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.MovieDetails["42"] = new TmdbMovieDetails("42", "Some Movie", 2020, "Synopsis", [], null, 7.8, 1234, null);
        var attemptedAt = DateTime.UtcNow.AddDays(-10);
        _movieReferenceRepository.Setup(r => r.FindByExternalIdAsync("tmdb", "42")).ReturnsAsync(new MovieReferenceModel
        {
            Id = "reference-1",
            Title = "Some Movie",
            TitleNormalized = "some movie",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            RatingsCheckedAt = new Dictionary<string, DateTime> { ["imdb"] = attemptedAt }
        });
        _movieReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>())).ReturnsAsync((MovieReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var result = await service.ResolveMovieAsync("Some Movie", 2020, "42");

        result.RatingsCheckedAt["imdb"].Should().Be(attemptedAt);
    }

    /// <summary>
    /// A movie reference that takes the cheap no-change short-circuit (already TMDB-rated, enriched days ago)
    /// and has no imdb rating - the shape every backfill test starts from. <paramref name="attemptedAt"/> is
    /// when OMDb was last asked about it, or null for never.
    /// </summary>
    private static MovieReferenceModel MovieReferenceAwaitingImdb(DateTime? attemptedAt) => new()
    {
        Id = "reference-1",
        Title = "Some Movie",
        TitleNormalized = "some movie",
        Year = 2020,
        ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
        LastEnrichedAt = DateTime.UtcNow.AddDays(-5),
        Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 1234 } },
        RatingsCheckedAt = attemptedAt is null ? [] : new Dictionary<string, DateTime> { ["imdb"] = attemptedAt.Value }
    };

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_ReStampsMovies_WithTheSelectedImdbSource()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["Movie"] = "imdb" });
        _movieReferenceRepository.Setup(r => r.FindRatingsAsync(null, It.IsAny<int>())).ReturnsAsync(
        [
            ("r1", new Dictionary<string, ReferenceRatingModel>
            {
                ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 1 }, ["imdb"] = new() { Value = 8.9, Scale = 10, Count = 2 }
            })
        ]);
        var written = CaptureRatingUpdates(_movieRepository, r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), itemsUpdatedPerBatch: 1);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (checkedCount, updated) = await service.RecomputeReferenceRatingsAsync(ReferenceItemType.Movie);

        checkedCount.Should().Be(1);
        updated.Should().Be(1);
        written.Should().ContainSingle().Which.Should().Equal(("r1", 8.9, 10, RatingSourceCatalog.Imdb));
    }

    [Fact]
    public async Task RefreshTvShowReferenceAsync_ReturnsUnchanged_WhenReferenceHasNoTmdbId()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        var service = CreateService(tmdbClient);
        var reference = new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", ExternalIds = [] };

        var (result, changed) = await service.RefreshTvShowReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.Should().BeSameAs(reference);
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()), Times.Never);
    }

    [Fact]
    public async Task RefreshTvShowReferenceAsync_OnlyBumpsLastEnrichedAt_WhenTmdbReportsNoChanges()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = false;
        var lastEnrichedAt = DateTime.UtcNow.AddDays(-5);
        var reference = new TvShowReferenceModel
        {
            Id = "reference-1",
            Title = "Some Show",
            TitleNormalized = "some show",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            // already has a rating, so the no-change short-circuit applies (an empty Ratings would instead
            // force a full backfill fetch - covered separately below)
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 8.0, Scale = 10, Count = 100 } },
            LastEnrichedAt = lastEnrichedAt
        };
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshTvShowReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.LastEnrichedAt.Should().BeAfter(lastEnrichedAt);
        // no changes reported: the expensive details/season fetch must never happen
        tmdbClient.TvShowDetailsRequested.Should().NotContain("42");
    }

    [Fact]
    public async Task RefreshTvShowReferenceAsync_RefetchesDetails_WhenTmdbReportsChanges()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.ChangedSince["42"] = true;
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show - Updated", 2020, "New synopsis", [], ["Drama"], null);
        var reference = new TvShowReferenceModel
        {
            Id = "reference-1",
            Title = "Some Show",
            TitleNormalized = "some show",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-5)
        };
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var (result, changed) = await service.RefreshTvShowReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Show - Updated");
        result.Synopsis.Should().Be("New synopsis");
        result.Genres.Should().Contain("Drama");
    }

    [Fact]
    public async Task RefreshTvShowReferenceAsync_RefetchesDetails_WhenNeverPreviouslyEnriched()
    {
        // no LastEnrichedAt to compare against: always do the full fetch, never call the changes pre-check
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        var reference = new TvShowReferenceModel
        {
            Id = "reference-1",
            Title = "Some Show",
            TitleNormalized = "some show",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "42" },
            LastEnrichedAt = null
        };
        _tvShowReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        var service = CreateService(tmdbClient);

        var (_, changed) = await service.RefreshTvShowReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        tmdbClient.ChangesRequested.Should().NotContain("42");
    }

    [Fact]
    public async Task TryAutoResolveBookAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var bookReferenceClient = FakeBookReferenceClient.WithSearchResults(
            new BookSearchResult("OL1W", "Some Book", 2020, "Some Author", null),
            new BookSearchResult("OL2W", "Some Book", 2020, "Some Author", null));
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.TryAutoResolveBookAsync("Some Book", 2020);

        _bookRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()),
            Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveBookAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var bookReferenceClient = FakeBookReferenceClient.WithSearchResults(new BookSearchResult("OL1W", "Some Book", 2020, "Some Author", null));
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id ??= "generated-id";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.TryAutoResolveBookAsync("Some Book", 2020);

        _bookReferenceRepository.Verify(r => r.UpsertAsync(It.Is<BookReferenceModel>(m => m.ExternalIds["openlibrary"] == "OL1W")), Times.Once);
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, It.IsAny<string>(), "Some Book", It.IsAny<int?>(), "Some Author", It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryAutoResolveBookAsync_PassesTheAuthorThroughToTheBookSearch()
    {
        // regression: a common title without an author hint returns many unrelated candidates - the
        // author must reach IBookReferenceClient.SearchBooksAsync, not just get dropped along the way.
        var bookReferenceClient = FakeBookReferenceClient.WithSearchResults(new BookSearchResult("OL1W", "Some Book", 2020, "Lee Child", null));
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Lee Child", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id ??= "generated-id";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.TryAutoResolveBookAsync("Killing Floor", 2016, "Lee Child");

        bookReferenceClient.LastSearchAuthor.Should().Be("Lee Child");
    }

    [Fact]
    public async Task ResolveBookAsync_PropagatesTheUpsertedReferenceId()
    {
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "OL1W");

        result.Id.Should().Be("reference-1");
        result.AuthorReferenceId.Should().Be("person-1");
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, "reference-1", "Some Book", It.IsAny<int?>(), "Some Author", It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    /// <summary>
    /// An exact-identifier field must only ever record the identifier that genuinely drove a given match,
    /// never backfilled from a different source onto an alias that didn't actually rely on it - the
    /// canonical alias (the provider's own reported data) and the tenant-search alias (what was actually
    /// searched with) are recorded as two distinct entries here, deliberately, not merged into one.
    /// </summary>
    [Fact]
    public async Task ResolveBookAsync_RecordsOnlyTheIsbnActuallyUsed_InEachMatchedAlias()
    {
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null, null, "9780000000002");
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "OL1W", isbn: "9780000000001");

        // the reference's own canonical Isbn always reflects the provider's own reported value...
        result.Isbn.Should().Be("9780000000002");
        // ...but the alias list keeps the two ISBNs as separate entries rather than one merged/overwritten value
        result.MatchedAliases.Should().Contain(a => a.Isbn == "9780000000001");
        result.MatchedAliases.Should().Contain(a => a.Isbn == "9780000000002");
    }

    [Fact]
    public async Task ResolveBookAsync_LeavesTheSearchAliasIsbnNull_WhenNoIsbnWasSupplied()
    {
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "OL1W");

        result.Isbn.Should().BeNull();
        result.MatchedAliases.Should().OnlyContain(a => a.Isbn == null);
    }

    [Fact]
    public async Task ResolveBookAsync_FallsBackToOpenLibraryRatingByIsbn_WhenTheLinkingProviderReportsNone()
    {
        // BnF (like Google Books, the production default) serves no rating; the resolved ISBN lets Open
        // Library supply one, stored under its own source key and denormalized as the book's primary rating.
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails("ark:/12148/cb1", "Some Book", 2020, "Synopsis", "Some Author", null, [], null, "fre", "9780000000001");
        _bookRatingByIsbnLookup.Result = (4.2, 100);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "ark:/12148/cb1", "bnf");

        _bookRatingByIsbnLookup.RequestedIsbns.Should().Contain("9780000000001");
        result.Ratings.Should().ContainKey("openlibrary");
        result.Ratings["openlibrary"].Value.Should().Be(4.2);
        result.Ratings["openlibrary"].Scale.Should().Be(5);
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, "reference-1", "Some Book", It.IsAny<int?>(),
            "Some Author", It.IsAny<string?>(), "fre", "9780000000001", 4.2, 5, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveBookAsync_DoesNotCallTheOpenLibraryFallback_WhenTheLinkingProviderIsOpenLibrary()
    {
        // the default provider IS Open Library here - a rating (or its absence) already comes from the link itself
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null, null, "9780000000001");
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.ResolveBookAsync("Some Book", 2020, "OL1W");

        _bookRatingByIsbnLookup.RequestedIsbns.Should().BeEmpty();
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_LinksAndUpdatesTitleAndAuthor_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel
        {
            Id = "book-1",
            OwnerId = "owner",
            Title = "Some Typo'd Book",
            Author = "Wrong Author",
            Year = 2020
        };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Book", 2020, "Wrong Author"))
            .ReturnsAsync(new BookReferenceModel
            {
                Id = "reference-1",
                Title = "Some Book",
                TitleNormalized = "some book",
                AuthorReferenceId = "person-1",
                ExternalIds = []
            });
        _personReferenceRepository
            .Setup(r => r.FindByIdAsync("person-1"))
            .ReturnsAsync(new PersonReferenceModel { Id = "person-1", Name = "Correct Author", ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1A" } });

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Book");
        result.Author.Should().Be("Correct Author");
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel
        {
            Id = "book-1",
            OwnerId = "owner",
            Title = "Some Book",
            Author = "Some Author",
            Year = 2019
        };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Book", 2019, "Some Author"))
            .ReturnsAsync(new BookReferenceModel
            {
                Id = "reference-1",
                Title = "Some Book",
                TitleNormalized = "some book",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.Year.Should().Be(2020);
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.Year == 2020), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_SetsGenreFromTheReferencesGenres_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel
        {
            Id = "book-1",
            OwnerId = "owner",
            Title = "Some Book",
            Author = "Some Author",
            Year = 2020
        };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Book", 2020, "Some Author"))
            .ReturnsAsync(new BookReferenceModel
            {
                Id = "reference-1",
                Title = "Some Book",
                TitleNormalized = "some book",
                ExternalIds = [],
                Genres = ["Thriller", "Mystery"]
            });

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.Genre.Should().Be("Thriller, Mystery");
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.Genre == "Thriller, Mystery"), "owner"), Times.Once);
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, "reference-1", "Some Book", It.IsAny<int?>(), It.IsAny<string?>(), "Thriller, Mystery", It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel
        {
            Id = "book-1",
            OwnerId = "owner",
            Title = "Some Book",
            Author = "Some Author",
            Year = 2020,
            ReferenceId = "old-reference"
        };
        _bookReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Book", 2020, "Some Author")).ReturnsAsync((BookReferenceModel?)null);
        _bookReferenceRepository.Setup(r => r.FindByTitleAsync("Some Book", "Some Author")).ReturnsAsync((BookReferenceModel?)null);

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task RefreshBookReferenceAsync_ReturnsUnchanged_WhenReferenceHasNoExternalId()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var reference = new BookReferenceModel { Id = "reference-1", Title = "Some Book", TitleNormalized = "some book", ExternalIds = [] };

        var (result, changed) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.Should().BeSameAs(reference);
        _bookReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<BookReferenceModel>()), Times.Never);
    }

    [Fact]
    public async Task RefreshBookReferenceAsync_AlwaysRefetches_RegardlessOfLastEnrichedAt()
    {
        // Open Library exposes no "changed since" endpoint (unlike TMDB) - every refresh call does a full
        // re-fetch, even when LastEnrichedAt is very recent.
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book - Updated", 2020, "New synopsis", "Some Author", "OL1A", ["Fiction"], null);
        var reference = new BookReferenceModel
        {
            Id = "reference-1",
            Title = "Some Book",
            TitleNormalized = "some book",
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1W" },
            LastEnrichedAt = DateTime.UtcNow
        };
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => m);
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var (result, changed) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Book - Updated");
        result.Genres.Should().Contain("Fiction");
    }

    /// <summary>
    /// Regression: Open Library's rating lookup is a *secondary* provider adding an optional number to a book
    /// the linking provider already returned in full, but an exception from it used to escape the whole
    /// refresh - so a slow Open Library discarded a complete BnF/Google Books response, skipped the upsert,
    /// and left <c>LastEnrichedAt</c> unstamped, which pinned those books at the head of the staleness queue
    /// to re-pay the same 40s timeout on every pass. Confirmed in the running app: 7 of 7 book references
    /// failed a forced sync this way while every other domain refreshed normally.
    /// </summary>
    [Fact]
    public async Task RefreshBookReferenceAsync_KeepsTheLinkingProvidersData_WhenTheOpenLibraryRatingLookupFails()
    {
        // bnf, not the default openlibrary: the fallback deliberately no-ops when the linking provider IS
        // Open Library, so the failure can only be reached through another provider.
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails(
            "ark:/12148/cb1", "Some Book - Updated", 2020, "Synopsis", "Some Author", null, ["Fiction"], null, "fre", "9780000000001");
        _bookRatingByIsbnLookup.Failure = new TimeoutException("Open Library took too long.");
        var reference = new BookReferenceModel
        {
            Id = "reference-1",
            Title = "Some Book",
            TitleNormalized = "some book",
            ExternalIds = new Dictionary<string, string> { ["bnf"] = "ark:/12148/cb1" },
            // obtained by an earlier successful lookup: the linking provider never carries this value, so a
            // refresh that couldn't reach Open Library must not be what deletes it ("The Hobbit"'s 4.29/498).
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["openlibrary"] = new() { Value = 4.29, Scale = 5, Count = 498 } },
            LastEnrichedAt = DateTime.UtcNow.AddDays(-30)
        };
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var (result, changed) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Book - Updated");
        result.Ratings["openlibrary"].Value.Should().Be(4.29);
        result.Ratings["openlibrary"].Count.Should().Be(498);
        // the half that keeps the staleness queue moving: an unstamped document is taken again on every pass
        result.LastEnrichedAt.Should().BeAfter(DateTime.UtcNow.AddMinutes(-1));
        _bookReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<BookReferenceModel>()), Times.Once);
    }

    /// <summary>
    /// The other side of that rule: Open Library answering "no rating for this ISBN" is a real answer, so the
    /// stored value goes - only a lookup that never happened is allowed to preserve it.
    /// </summary>
    [Fact]
    public async Task RefreshBookReferenceAsync_ClearsAKnownRating_WhenOpenLibraryAnswersWithNoRating()
    {
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails(
            "ark:/12148/cb1", "Some Book", 2020, "Synopsis", "Some Author", null, [], null, "fre", "9780000000001");
        _bookRatingByIsbnLookup.Result = (null, null);
        var reference = new BookReferenceModel
        {
            Id = "reference-1",
            Title = "Some Book",
            TitleNormalized = "some book",
            ExternalIds = new Dictionary<string, string> { ["bnf"] = "ark:/12148/cb1" },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["openlibrary"] = new() { Value = 4.29, Scale = 5, Count = 498 } }
        };
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var (result, _) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.Ratings.Should().BeEmpty();
    }

    /// <summary>
    /// The same guard on the interactive path, where the throw surfaced as a 500 from admin manual linking
    /// (and from the auto-resolve a book creation fires) despite the linking provider having answered.
    /// </summary>
    [Fact]
    public async Task ResolveBookAsync_StillLinks_WhenTheOpenLibraryRatingLookupFails()
    {
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails(
            "ark:/12148/cb1", "Some Book", 2020, "Synopsis", "Some Author", null, [], null, "fre", "9780000000001");
        _bookRatingByIsbnLookup.Failure = new System.Net.Http.HttpRequestException("Open Library is down.");
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id ??= "reference-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "ark:/12148/cb1", "bnf");

        result.Id.Should().Be("reference-1");
        result.Ratings.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshBookReferenceAsync_RefreshesViaANonDefaultRegisteredProvider_WhenThatsTheOnlyOnePresent()
    {
        // regression: this used to only ever check the currently-configured DEFAULT provider's key, so a
        // reference linked through any other registered provider (bnf here, openlibrary being the default)
        // would silently stop refreshing forever.
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails("ark:/12148/cb1", "Some Book - Updated", 2020, "Synopsis", "Some Author", null, [], null, "fre");
        var reference = new BookReferenceModel
        {
            Id = "reference-1",
            Title = "Some Book",
            TitleNormalized = "some book",
            ExternalIds = new Dictionary<string, string> { ["bnf"] = "ark:/12148/cb1" },
            LastEnrichedAt = DateTime.UtcNow
        };
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var (result, changed) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Book - Updated");
        result.Language.Should().Be("fre");
    }

    [Fact]
    public async Task ResolveBookAsync_UsesTheExplicitlyRequestedProvider_NotTheDefault()
    {
        var bnfClient = FakeBnfClient.Empty();
        bnfClient.Details["ark:/12148/cb1"] = new BookDetails("ark:/12148/cb1", "Some Book", 2020, "Synopsis", "Some Author", null, [], null, "fre");
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "ark:/12148/cb1", "bnf");

        result.ExternalIds["bnf"].Should().Be("ark:/12148/cb1");
        result.ExternalIds.Should().NotContainKey("openlibrary");
        result.Language.Should().Be("fre");
    }

    [Fact]
    public async Task TryAutoResolveVideoGameAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var videoGameClient = FakeVideoGameReferenceClient.WithSearchResults(
            new VideoGameSearchResult("1", "Some Game", 2020, null),
            new VideoGameSearchResult("2", "Some Game", 2020, null));
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        await service.TryAutoResolveVideoGameAsync("Some Game", 2020);

        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveVideoGameAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var videoGameClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("1", "Some Game", 2020, null));
        videoGameClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) =>
        {
            m.Id ??= "generated-id";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        await service.TryAutoResolveVideoGameAsync("Some Game", 2020);

        _videoGameReferenceRepository.Verify(r => r.UpsertAsync(It.Is<VideoGameReferenceModel>(m => m.ExternalIds["igdb"] == "1")), Times.Once);
        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync("Some Game", 2020, It.IsAny<string>(), "Some Game", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveVideoGameAsync_PropagatesTheUpsertedReferenceId()
    {
        var videoGameClient = FakeVideoGameReferenceClient.Empty();
        videoGameClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        var result = await service.ResolveVideoGameAsync("Some Game", 2020, "1");

        result.Id.Should().Be("reference-1");
        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync("Some Game", 2020, "reference-1", "Some Game", It.IsAny<int?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    // --- Admin-selectable primary rating source (RatingSourceCatalog + IAppSettingRepository) ---

    [Fact]
    public async Task GetPrimaryRatingSourceAsync_ReturnsCodeDefault_WhenNoOverrideIsStored()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var source = await service.GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame);

        source.Should().Be(RatingSourceCatalog.Igdb);
    }

    [Fact]
    public async Task GetPrimaryRatingSourceAsync_ReturnsTheOverride_WhenAnAdminHasSetAValidSource()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.IgdbCritic });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var source = await service.GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame);

        source.Should().Be(RatingSourceCatalog.IgdbCritic);
    }

    [Fact]
    public async Task GetPrimaryRatingSourceAsync_IgnoresAStoredMetacriticOverride_NowThatNoRegisteredProviderReportsIt()
    {
        // the same fate RAWG's own score met when it stopped being the default: the key stays declared so
        // stored values keep rendering, but it leaves the selectable list, and Resolve then falls back to the
        // current default. Without that, every game linked since the provider change resolved to no rating at
        // all - IGDB never writes a metacritic value, so there was nothing for the primary source to read.
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.Metacritic });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var source = await service.GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame);

        source.Should().Be(RatingSourceCatalog.Igdb);
    }

    [Fact]
    public async Task GetPrimaryRatingSourceAsync_FallsBackToTheDefault_WhenTheStoredOverrideIsNoLongerAvailable()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = "some-removed-source" });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var source = await service.GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame);

        source.Should().Be(RatingSourceCatalog.Igdb);
    }

    [Fact]
    public async Task ResolveVideoGameAsync_DenormalizesTheCriticAggregate_WhenItIsTheSelectedPrimarySource()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.IgdbCritic });
        // a provider reports two scores on two scales, and which of them a tenant item carries is the admin's
        // choice - here the critic aggregate rather than the user score the domain defaults to.
        var videoGameClient = FakeVideoGameReferenceClient.Empty();
        videoGameClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null, new Dictionary<string, ReferenceRatingModel>
        {
            [RatingSourceCatalog.Igdb] = new() { Value = 80, Scale = 100, Count = 100 },
            [RatingSourceCatalog.IgdbCritic] = new() { Value = 90, Scale = 100 }
        });
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        await service.ResolveVideoGameAsync("Some Game", 2020, "1");

        // the selected source drives which of the provider's two numbers is denormalized onto tenant items.
        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync("Some Game", 2020, "reference-1", "Some Game", It.IsAny<int?>(), 90, 100, It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_ReStampsEveryLinkedItem_WithTheSelectedSourcesRating()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.IgdbCritic });
        _videoGameReferenceRepository.Setup(r => r.FindRatingsAsync(null, It.IsAny<int>())).ReturnsAsync(
        [
            GameRatings("r1", igdb: 92, critic: 90),
            GameRatings("r2", igdb: 71, critic: 60)
        ]);
        var written = CaptureRatingUpdates(_videoGameRepository, r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), itemsUpdatedPerBatch: 2);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (referencesChecked, itemsUpdated) = await service.RecomputeReferenceRatingsAsync(ReferenceItemType.VideoGame);

        referencesChecked.Should().Be(2);
        itemsUpdated.Should().Be(2);
        // both references travel in one bulk write, not one round trip each
        written.Should().ContainSingle().Which.Should().Equal(
            ("r1", 90, 100, RatingSourceCatalog.IgdbCritic),
            ("r2", 60, 100, RatingSourceCatalog.IgdbCritic));
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_PagesWithACursor_AndStopsOnTheFirstShortPage()
    {
        // a full page means there may be more behind it, so the next read continues *after* the last id
        // rather than starting over; a short page is the end and costs no further query.
        var firstPage = Enumerable.Range(0, 500).Select(i => GameRatings($"r{i}", igdb: 92, critic: 90)).ToList();
        _videoGameReferenceRepository.Setup(r => r.FindRatingsAsync(null, It.IsAny<int>())).ReturnsAsync(firstPage);
        _videoGameReferenceRepository.Setup(r => r.FindRatingsAsync("r499", It.IsAny<int>()))
            .ReturnsAsync([GameRatings("r500", igdb: 92, critic: 90)]);
        _videoGameRepository.Setup(r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>())).ReturnsAsync(1);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (referencesChecked, _) = await service.RecomputeReferenceRatingsAsync(ReferenceItemType.VideoGame);

        referencesChecked.Should().Be(501);
        _videoGameReferenceRepository.Verify(r => r.FindRatingsAsync(It.IsAny<string?>(), It.IsAny<int>()), Times.Exactly(2));
        _videoGameRepository.Verify(r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), Times.Exactly(2));
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_UsesTheCodeDefaultSource_WhenNoOverrideIsStored()
    {
        _videoGameReferenceRepository.Setup(r => r.FindRatingsAsync(null, It.IsAny<int>())).ReturnsAsync(
        [
            GameRatings("r1", igdb: 92, critic: 90)
        ]);
        var written = CaptureRatingUpdates(_videoGameRepository, r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), itemsUpdatedPerBatch: 1);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.RecomputeReferenceRatingsAsync(ReferenceItemType.VideoGame);

        // IGDB's own score is the default, not Metacritic's.
        written.Should().ContainSingle().Which.Should().Equal(("r1", 92, 100, RatingSourceCatalog.Igdb));
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_Throws_ForADomainWhoseSourceIsNotAdminSelectable()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        // Album is still single-source (Book/Album haven't gained a second source), so it's not recomputable
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.RecomputeReferenceRatingsAsync(ReferenceItemType.Album));
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_DoesNothing_WhenEveryItemIsAlreadyOnTheSelectedSource()
    {
        // nothing is stamped with anything other than the selected source - the ordinary case, since the
        // action sits next to the source picker and gets clicked again "just in case"
        _videoGameRepository.Setup(r => r.CountLinkedOnOtherRatingSourceAsync(It.IsAny<string>())).ReturnsAsync(0);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (referencesChecked, itemsUpdated) = await service.RecomputeReferenceRatingsAsync(ReferenceItemType.VideoGame);

        referencesChecked.Should().Be(0);
        itemsUpdated.Should().Be(0);
        // the whole point: the reference collection isn't even read, let alone re-stamped with values that
        // are already correct
        _videoGameReferenceRepository.Verify(r => r.FindRatingsAsync(It.IsAny<string?>(), It.IsAny<int>()), Times.Never);
        _videoGameRepository.Verify(r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), Times.Never);
    }

    [Fact]
    public async Task RecomputeReferenceRatingsAsync_StampsTheSelectedSource_EvenWhenItHasNoValueForThatReference()
    {
        _appSettingRepository.Setup(r => r.GetReferenceRatingSourcesAsync())
            .ReturnsAsync(new Dictionary<string, string> { ["VideoGame"] = RatingSourceCatalog.IgdbCritic });
        _videoGameReferenceRepository.Setup(r => r.FindRatingsAsync(null, It.IsAny<int>())).ReturnsAsync(
        [
            GameRatings("r1", igdb: 92, critic: null)
        ]);
        var written = CaptureRatingUpdates(_videoGameRepository, r => r.SetReferenceRatingsAsync(It.IsAny<RatingUpdateBatch>()), itemsUpdatedPerBatch: 1);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.RecomputeReferenceRatingsAsync(ReferenceItemType.VideoGame);

        // the stamp records which source was applied, not where a number came from. Leaving it null here
        // would leave this item looking mismatched forever, so recompute could never report "nothing to do".
        written.Should().ContainSingle().Which.Should().Equal(("r1", null, null, RatingSourceCatalog.IgdbCritic));
    }

    /// <summary>
    /// Stubs a tenant repository's bulk re-stamp and hands back the list the batches land in, one entry per
    /// bulk write. A captured batch is asserted with ordinary assertions afterwards: Moq's <c>It.Is</c> takes
    /// an expression tree, and an expression tree may hold neither a tuple literal nor a tuple <c>==</c>, so
    /// matching a batch inline is not an option here (CS8143/CS8382).
    /// </summary>
    private static List<RatingUpdateBatch> CaptureRatingUpdates<TRepository>(
        Mock<TRepository> repository,
        Expression<Func<TRepository, Task<long>>> setReferenceRatings,
        long itemsUpdatedPerBatch)
        where TRepository : class
    {
        var batches = new List<RatingUpdateBatch>();
        repository.Setup(setReferenceRatings).Callback<RatingUpdateBatch>(batches.Add).ReturnsAsync(itemsUpdatedPerBatch);
        return batches;
    }

    /// <summary>
    /// One entry of what the recompute's projected read returns for a game reference carrying two sources -
    /// pass a null <paramref name="critic"/> for the common case of a game the press never scored.
    /// </summary>
    private static (string Id, Dictionary<string, ReferenceRatingModel> Ratings) GameRatings(string id, double igdb, double? critic) =>
    (
        id,
        critic is null
            ? new Dictionary<string, ReferenceRatingModel> { [RatingSourceCatalog.Igdb] = new() { Value = igdb, Scale = 100, Count = 100 } }
            : new Dictionary<string, ReferenceRatingModel>
            {
                [RatingSourceCatalog.Igdb] = new() { Value = igdb, Scale = 100, Count = 100 },
                [RatingSourceCatalog.IgdbCritic] = new() { Value = critic.Value, Scale = 100 }
            }
    );

    [Fact]
    public async Task TryLinkExistingVideoGameReferenceAsync_LinksAndUpdatesTitle_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new VideoGameModel
        {
            Id = "game-1",
            OwnerId = "owner",
            Title = "Some Typo'd Game",
            Year = 2020,
            Platforms = [new VideoGamePlatformModel { Platform = "PC", State = "Current" }]
        };
        _videoGameReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Game", 2020))
            .ReturnsAsync(new VideoGameReferenceModel { Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", ExternalIds = [] });

        var result = await service.TryLinkExistingVideoGameReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Game");
        result.Platforms.Should().ContainSingle(p => p.Platform == "PC");
        _videoGameRepository.Verify(r => r.UpdateAsync("game-1", It.Is<VideoGameModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingVideoGameReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new VideoGameModel
        {
            Id = "game-1",
            OwnerId = "owner",
            Title = "Some Game",
            Year = 2019,
            Platforms = [new VideoGamePlatformModel { Platform = "PC", State = "Current" }]
        };
        _videoGameReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Game", 2019))
            .ReturnsAsync(new VideoGameReferenceModel
            {
                Id = "reference-1",
                Title = "Some Game",
                TitleNormalized = "some game",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingVideoGameReferenceAsync(model);

        result.Year.Should().Be(2020);
        _videoGameRepository.Verify(r => r.UpdateAsync("game-1", It.Is<VideoGameModel>(m => m.Year == 2020), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingVideoGameReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new VideoGameModel
        {
            Id = "game-1",
            OwnerId = "owner",
            Title = "Some Game",
            Year = 2020,
            ReferenceId = "old-reference",
            Platforms = [new VideoGamePlatformModel { Platform = "PC", State = "Current" }]
        };
        _videoGameReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Game", 2020)).ReturnsAsync((VideoGameReferenceModel?)null);
        _videoGameReferenceRepository.Setup(r => r.FindByTitleAsync("Some Game")).ReturnsAsync((VideoGameReferenceModel?)null);

        var result = await service.TryLinkExistingVideoGameReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _videoGameRepository.Verify(r => r.UpdateAsync("game-1", It.Is<VideoGameModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_StampsItAsChecked_WhenNoProviderIdCouldBeResolved()
    {
        // nothing was fetched, but the pass still has to record that it looked: FindStaleAsync serves the
        // least-recently-enriched first under a per-pass cap, so a document whose LastEnrichedAt never moves
        // would sit at the head of that queue forever and starve everything behind it.
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var reference = new VideoGameReferenceModel { Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", ExternalIds = [] };

        var (result, changed) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.LastEnrichedAt.Should().NotBeNull();
        result.ExternalIds.Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_AlwaysRefetches_RegardlessOfLastEnrichedAt()
    {
        // no video game provider exposes a "changed since" endpoint (unlike TMDB) - every refresh call does a
        // full re-fetch, even when LastEnrichedAt is very recent.
        var videoGameClient = FakeVideoGameReferenceClient.Empty();
        videoGameClient.Details["1"] = new VideoGameDetails("1", "Some Game - Updated", 2020, "New synopsis", ["Action"], ["PC"], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "1" },
            LastEnrichedAt = DateTime.UtcNow
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        var (result, changed) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Game - Updated");
        result.Platforms.Should().Contain("PC");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_NeverCallsAProviderOtherThanTheDefault()
    {
        // deliberately unlike RefreshBookReferenceAsync's "refresh through whichever provider linked it": this
        // domain gained a second provider *because the first went down*, so falling back to it would make every
        // not-yet-adopted reference pay a retry-and-timeout cycle against a dead host on every pass. The
        // reference keeps the data (and the ids) it already has instead.
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        rawgClient.Details["7"] = new VideoGameDetails("7", "Some Game - Updated", 2020, "New synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        var (result, changed) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        // RAWG's details would have renamed it; the title staying put is what proves RAWG was never called
        result.Title.Should().Be("Some Game");
        result.ExternalIds.Should().ContainKey("rawg").WhoseValue.Should().Be("7");
        result.LastEnrichedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_KeepsRatingsFromTheOtherProvider()
    {
        // the whole point of merging rather than assigning: a refresh through IGDB may only speak for IGDB's
        // own sources, and must leave a still-perfectly-good RAWG/Metacritic score on the document (it is
        // still shown on the detail page, and re-earning it would cost a call to a provider that may be down).
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null, new Dictionary<string, ReferenceRatingModel>
        {
            [RatingSourceCatalog.Igdb] = new() { Value = 92, Scale = 100, Count = 500 }
        });
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "1" },
            Ratings = new Dictionary<string, ReferenceRatingModel>
            {
                [RatingSourceCatalog.Rawg] = new() { Value = 4.5, Scale = 5, Count = 100 },
                [RatingSourceCatalog.Metacritic] = new() { Value = 88, Scale = 100 }
            }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.Ratings.Should().ContainKey(RatingSourceCatalog.Igdb).WhoseValue.Value.Should().Be(92);
        result.Ratings.Should().ContainKey(RatingSourceCatalog.Rawg).WhoseValue.Value.Should().Be(4.5);
        result.Ratings.Should().ContainKey(RatingSourceCatalog.Metacritic).WhoseValue.Value.Should().Be(88);
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_DropsItsOwnSource_WhenTheProviderNoLongerReportsIt()
    {
        // the other half of the merge rule: a provider saying "I have no critic score for this" is an answer,
        // so its own stale value goes - only *other* providers' values are untouchable.
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null, new Dictionary<string, ReferenceRatingModel>
        {
            [RatingSourceCatalog.Igdb] = new() { Value = 92, Scale = 100 }
        });
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "1" },
            Ratings = new Dictionary<string, ReferenceRatingModel>
            {
                [RatingSourceCatalog.IgdbCritic] = new() { Value = 80, Scale = 100 }
            }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.Ratings.Should().NotContainKey(RatingSourceCatalog.IgdbCritic);
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_AdoptsTheDefaultProvidersId_OnAnExactTitleMatch()
    {
        // how a catalogue crosses a provider change without a migration script: the reference was linked
        // through RAWG, and one search per pass gives it an IGDB id it can be refreshed and rated through.
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", "Some Game", 2020, null));
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], null);
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
        // and the RAWG id it was linked through is kept, not replaced
        result.ExternalIds.Should().ContainKey("rawg").WhoseValue.Should().Be("7");
    }

    [Theory]
    [InlineData("Some Other Game", 2020)] // the title doesn't actually match
    [InlineData("Some Game", 1999)]       // right title, a different game's year
    public async Task RefreshVideoGameReferenceAsync_DoesNotAdopt_WhenTheMatchIsNotExact(string candidateTitle, int candidateYear)
    {
        // "don't guess": two different games sharing a title is ordinary, so anything short of an exact match
        // is left for an admin to link by hand rather than silently attached to the wrong game.
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", candidateTitle, candidateYear, null));
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        rawgClient.Details["7"] = new VideoGameDetails("7", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().NotContainKey("igdb");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_DoesNotSearchAtAll_OnceTheDefaultProvidersIdIsPresent()
    {
        // adoption must stop costing a call the moment it has succeeded, or every pass would re-pay for it
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", "Some Game", 2020, null));
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "42" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        igdbClient.SearchCount.Should().Be(0);
    }

    [Theory]
    // the divergences that actually blocked adoption on real data - a colon, an article, and RAWG's habit of
    // disambiguating a remake by putting the original's year in the title
    [InlineData("Mass Effect: Legendary Edition", "Mass Effect Legendary Edition")]
    [InlineData("Disco Elysium: Final Cut", "Disco Elysium: The Final Cut")]
    [InlineData("GoldenEye 007 (1997)", "GoldenEye 007")]
    public async Task RefreshVideoGameReferenceAsync_Adopts_WhenTheProviderSpellsTheSameTitleDifferently(string referenceTitle, string providerTitle)
    {
        // exact normalized equality rejected every one of these, which is what left a third of a real
        // catalogue stuck on the old provider - and, since Explore excludes owned titles the same way, kept
        // suggesting those games to the owner who already had them
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", providerTitle, 2020, null));
        igdbClient.Details["42"] = new VideoGameDetails("42", providerTitle, 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = referenceTitle,
            TitleNormalized = TitleNormalizer.Normalize(referenceTitle),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_AsksForTheExactTitleFirst_AndOnlyWidensWhenItFindsNothing()
    {
        // the relevance search is documented as noisy enough to push the canonical entry out of the result
        // window entirely, so adoption asks the narrow question first and widens only on an empty answer
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("99", "Some Game: Definitive Edition", 2020, null));
        igdbClient.ExactTitleResults.Add(new VideoGameSearchResult("42", "Some Game", 2020, null));
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
        igdbClient.ExactTitleSearchCount.Should().Be(1);
        igdbClient.SearchCount.Should().Be(0); // the exact answer was enough - no widening
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_RetriesWithoutTheDisambiguator_WhenTheTitleAsStoredFindsNothing()
    {
        // RAWG disambiguates a remake by putting the original's year in the title. Confirmed live: IGDB
        // returns *nothing at all* for "GoldenEye 007 (1997)" - from both its queries - so there is no
        // candidate list a looser comparison could rescue. Only re-asking with the bare title finds the game.
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.ExactTitleResults.Add(new VideoGameSearchResult("42", "Some Game", 2016, null));
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2016, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game (2016)",
            TitleNormalized = "some game (2016)",
            Year = 2016,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
        igdbClient.ExactTitleSearchCount.Should().Be(2); // the stored title, then the stripped one
        igdbClient.SearchCount.Should().Be(0);           // which answered, so no widening to relevance search
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_DoesNotReSearch_WhenAdoptionWasAlreadyAttemptedRecently()
    {
        // a title the provider has no unambiguous match for cannot be searched into working, so re-asking on
        // every pass buys nothing and costs two calls per stuck reference, forever
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", "Some Game", 2020, null));
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        rawgClient.Details["7"] = new VideoGameDetails("7", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" },
            ProviderAdoptionCheckedAt = new Dictionary<string, DateTime> { ["igdb"] = DateTime.UtcNow.AddDays(-1) }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        igdbClient.ExactTitleSearchCount.Should().Be(0);
        igdbClient.SearchCount.Should().Be(0);
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_RecordsAFruitlessAdoptionAttempt()
    {
        // stamped even though nothing was adopted: that record is what stops the next pass re-paying for the
        // same answer, and what lets the admin queue show "tried, and the provider has no match"
        var igdbClient = FakeVideoGameReferenceClient.WithSearchResults(new VideoGameSearchResult("42", "A Different Game", 2020, null));
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ExternalIds.Should().NotContainKey("igdb");
        result.ProviderAdoptionCheckedAt.Should().ContainKey("igdb");
        // and it was persisted, not just set on the in-memory copy
        _videoGameReferenceRepository.Verify(r => r.UpsertAsync(It.Is<VideoGameReferenceModel>(m => m.ProviderAdoptionCheckedAt.ContainsKey("igdb"))), Times.Once);
    }

    // --- Admin provider reconciliation: adopting a picked id, and merging two documents for one work ---

    [Fact]
    public async Task AdoptVideoGameProviderIdAsync_AddsTheIdToTheExistingDocument_RatherThanCreatingASecondOne()
    {
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-1")).ReturnsAsync(reference);
        _videoGameReferenceRepository.Setup(r => r.FindByExternalIdAsync("igdb", "42")).ReturnsAsync((VideoGameReferenceModel?)null);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var result = await service.AdoptVideoGameProviderIdAsync("reference-1", "42", TestContext.Current.CancellationToken);

        result.Id.Should().Be("reference-1");
        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
        result.ExternalIds.Should().ContainKey("rawg").WhoseValue.Should().Be("7");
    }

    [Fact]
    public async Task AdoptVideoGameProviderIdAsync_Refuses_WhenAnotherDocumentAlreadyClaimsThatId()
    {
        // the unique partial index would reject the write anyway; failing here names the other document, which
        // is what turns "it didn't work" into "merge these two"
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7" }
        };
        var claimant = new VideoGameReferenceModel
        {
            Id = "reference-2", Title = "Some Game", TitleNormalized = "some game", Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "42" }
        };
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-1")).ReturnsAsync(reference);
        _videoGameReferenceRepository.Setup(r => r.FindByExternalIdAsync("igdb", "42")).ReturnsAsync(claimant);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var act = () => service.AdoptVideoGameProviderIdAsync("reference-1", "42", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*already belongs*");
    }

    [Fact]
    public async Task MergeVideoGameReferencesAsync_UnionsWhatEachKnew_AndRePointsTheTenantsItems()
    {
        // the state a provider change (or a reference-data import from an environment on another provider)
        // leaves behind: one work, two documents, its ids and ratings split between them
        var keep = new VideoGameReferenceModel
        {
            Id = "reference-1", Title = "Elden Ring", TitleNormalized = "elden ring", Year = 2022,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "326243" },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["rawg"] = new() { Value = 4.38, Scale = 5 } },
            ImageUrl = "https://media.rawg.io/elden-ring.jpg"
        };
        var absorbed = new VideoGameReferenceModel
        {
            Id = "reference-2", Title = "Elden Ring", TitleNormalized = "elden ring", Year = 2022,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "119133" },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["igdb"] = new() { Value = 93.4, Scale = 100 } }
        };
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-1")).ReturnsAsync(keep);
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-2")).ReturnsAsync(absorbed);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        _videoGameRepository.Setup(r => r.RepointReferenceAsync("reference-2", "reference-1")).ReturnsAsync(3);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (kept, itemsRepointed) = await service.MergeVideoGameReferencesAsync("reference-1", "reference-2");

        kept.ExternalIds.Should().ContainKeys("rawg", "igdb");
        kept.Ratings.Should().ContainKeys("rawg", "igdb");
        kept.ImageUrl.Should().Be("https://media.rawg.io/elden-ring.jpg");
        itemsRepointed.Should().Be(3);
        _videoGameReferenceRepository.Verify(r => r.DeleteAsync("reference-2"), Times.Once);
        // items move before the document they pointed at is gone for good
        _videoGameRepository.Verify(r => r.RepointReferenceAsync("reference-2", "reference-1"), Times.Once);
    }

    [Fact]
    public async Task MergeVideoGameReferencesAsync_KeepsTheRawgCover_EvenWhenTheAdminKeepsTheIgdbDocument()
    {
        // the same rule PreferredImageUrl applies to a refresh: RAWG's curated key art is irreplaceable (its
        // CDN still serves those URLs, but the URL cannot be recomputed from the id without RAWG's API),
        // IGDB's box art is a downgrade, and a merge is exactly where that loss would happen unnoticed - the
        // duplicate pair is typically one RAWG-era document and one IGDB-era one.
        var keep = new VideoGameReferenceModel
        {
            Id = "reference-1", Title = "Elden Ring", TitleNormalized = "elden ring", Year = 2022,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "119133" },
            ImageUrl = "https://images.igdb.com/elden-ring.jpg"
        };
        var absorbed = new VideoGameReferenceModel
        {
            Id = "reference-2", Title = "Elden Ring", TitleNormalized = "elden ring", Year = 2022,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "326243" },
            ImageUrl = "https://media.rawg.io/elden-ring.jpg"
        };
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-1")).ReturnsAsync(keep);
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-2")).ReturnsAsync(absorbed);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        _videoGameRepository.Setup(r => r.RepointReferenceAsync("reference-2", "reference-1")).ReturnsAsync(1);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (kept, _) = await service.MergeVideoGameReferencesAsync("reference-1", "reference-2");

        kept.ImageUrl.Should().Be("https://media.rawg.io/elden-ring.jpg");
    }

    [Fact]
    public async Task MergeVideoGameReferencesAsync_KeepsTheSurvivorsCover_WhenNeitherDocumentIsRawgLinked()
    {
        // the rule is about RAWG's key art specifically, not about preferring the absorbed document - with no
        // rawg id in play the ordinary "never overwrite the survivor" rule applies.
        var keep = new VideoGameReferenceModel
        {
            Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "1" },
            ImageUrl = "https://images.igdb.com/kept.jpg"
        };
        var absorbed = new VideoGameReferenceModel
        {
            Id = "reference-2", Title = "Some Game", TitleNormalized = "some game", Year = 2020,
            ExternalIds = [],
            ImageUrl = "https://images.igdb.com/absorbed.jpg"
        };
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-1")).ReturnsAsync(keep);
        _videoGameReferenceRepository.Setup(r => r.FindByIdAsync("reference-2")).ReturnsAsync(absorbed);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        _videoGameRepository.Setup(r => r.RepointReferenceAsync("reference-2", "reference-1")).ReturnsAsync(0);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        var (kept, _) = await service.MergeVideoGameReferencesAsync("reference-1", "reference-2");

        kept.ImageUrl.Should().Be("https://images.igdb.com/kept.jpg");
    }

    // --- Cover art: RAWG's key art is protected from every provider except RAWG itself (PreferredImageUrl) ---

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_KeepsTheRawgCover_WhenRefreshingThroughIgdb()
    {
        // RAWG's background_image is curated landscape key art and its CDN still serves it even though its API
        // is gone; IGDB's portrait box art is a downgrade, and the RAWG URL can't be recomputed from the RAWG
        // id once overwritten. This is the normal state after adoption: both ids on one document.
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], "https://images.igdb.com/igdb/image/upload/t_1080p/abc.jpg");
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7", ["igdb"] = "42" },
            ImageUrl = "https://media.rawg.io/media/games/some-game.jpg"
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ImageUrl.Should().Be("https://media.rawg.io/media/games/some-game.jpg");
        // everything else the refresh fetched still lands - only the image is held back
        result.Synopsis.Should().Be("Synopsis");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_TakesTheFetchedCover_WhenTheReferenceCarriesNoRawgId()
    {
        // nothing to protect: a reference that never went through RAWG refreshes its image like any other field
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], "https://images.igdb.com/igdb/image/upload/t_1080p/new.jpg");
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "42" },
            ImageUrl = "https://images.igdb.com/igdb/image/upload/t_1080p/old.jpg"
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ImageUrl.Should().Be("https://images.igdb.com/igdb/image/upload/t_1080p/new.jpg");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_TakesTheFetchedCover_WhenTheRawgLinkedReferenceHasNoStoredImage()
    {
        // the guard protects a *stored* RAWG image, not the RAWG id: with nothing stored, any cover beats none
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], "https://images.igdb.com/igdb/image/upload/t_1080p/abc.jpg");
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "7", ["igdb"] = "42" },
            ImageUrl = null
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ImageUrl.Should().Be("https://images.igdb.com/igdb/image/upload/t_1080p/abc.jpg");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_KeepsTheStoredCover_WhenTheProviderReturnsNone()
    {
        // "never overwrite with nothing", the same rule SetReferenceLinkAsync follows for every other field
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        igdbClient.Details["42"] = new VideoGameDetails("42", "Some Game", 2020, "Synopsis", [], [], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "42" },
            ImageUrl = "https://images.igdb.com/igdb/image/upload/t_1080p/old.jpg"
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.ImageUrl.Should().Be("https://images.igdb.com/igdb/image/upload/t_1080p/old.jpg");
    }

    [Fact]
    public async Task ResolveVideoGameAsync_TakesTheRawgCover_WhenAnAdminRelinksThroughRawg()
    {
        // Regression: the guard used to key on "the document carries a RAWG id" alone, which fires against RAWG
        // itself. The admin picker passes its provider straight through to here, so re-linking a reference
        // through RAWG added the RAWG id first and then discarded the key art it had just fetched in favour of
        // the stored IGDB cover - the exact inversion of the rule's intent, and the only way to repair a dead
        // RAWG image short of unlinking (which deletes the shared reference document).
        var igdbClient = FakeVideoGameReferenceClient.Empty();
        var rawgClient = FakeVideoGameReferenceClient.Empty(RatingSourceCatalog.Rawg);
        rawgClient.Details["7"] = new VideoGameDetails("7", "Some Game", 2020, "Synopsis", [], [], "https://media.rawg.io/media/games/some-game.jpg");
        _videoGameReferenceRepository.Setup(r => r.FindByExternalIdAsync(RatingSourceCatalog.Rawg, "7")).ReturnsAsync((VideoGameReferenceModel?)null);
        _videoGameReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Game", 2020)).ReturnsAsync(new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "42" },
            ImageUrl = "https://images.igdb.com/igdb/image/upload/t_1080p/abc.jpg"
        });
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: igdbClient, secondaryVideoGameClient: rawgClient);

        var result = await service.ResolveVideoGameAsync("Some Game", 2020, "7", RatingSourceCatalog.Rawg);

        result.ImageUrl.Should().Be("https://media.rawg.io/media/games/some-game.jpg");
        result.ExternalIds.Should().ContainKey("igdb").WhoseValue.Should().Be("42");
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_DoesNotDuplicateAnAliasAlreadyPersistedWithANullCreator()
    {
        // Regression: MergeMatchedAliases must recognize an existing alias with Creator = null as the same
        // alias it's about to re-add with a freshly-computed null Creator (TV show/movie/video game domains
        // have no creator dimension), or every refresh appends a fresh, indistinguishable duplicate forever.
        // This used to fail because a null Creator silently round-tripped through Mongo as "" (a global
        // AllowNullDestinationValues = false default), which the in-memory comparison here didn't account
        // for - confirmed against a real RAWG-backed video game reference ("God of War") that had
        // accumulated an exact duplicate {title, year, creator: ""} entry from being resolved/refreshed
        // more than once. Fixed at the mapping layer instead (DataStorageMappingProfile opts Creator out of
        // AllowNullDestinationValues, so it stays a real null in Mongo) rather than papering over it here.
        var videoGameClient = FakeVideoGameReferenceClient.Empty();
        videoGameClient.Details["1"] = new VideoGameDetails("1", "Some Game", 2020, "Synopsis", ["Action"], ["PC"], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = "some game", Year = 2020, Creator = null }]
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), videoGameClient: videoGameClient);

        var (result, _) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        result.MatchedAliases.Should().ContainSingle();
    }

    [Fact]
    public async Task TryAutoResolveAlbumAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var discogsClient = FakeDiscogsClient.WithSearchResults(
            new DiscogsSearchResult("1", "Some Album", 2020, "Some Artist", null),
            new DiscogsSearchResult("2", "Some Album", 2020, "Some Artist", null));
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        await service.TryAutoResolveAlbumAsync("Some Album", 2020);

        _albumRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()),
            Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveAlbumAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var discogsClient = FakeDiscogsClient.WithSearchResults(new DiscogsSearchResult("1", "Some Album", 2020, "Some Artist", null));
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Some Artist", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) =>
        {
            m.Id ??= "generated-id";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        await service.TryAutoResolveAlbumAsync("Some Album", 2020);

        _albumReferenceRepository.Verify(r => r.UpsertAsync(It.Is<AlbumReferenceModel>(m => m.ExternalIds["discogs"] == "1")), Times.Once);
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, It.IsAny<string>(), "Some Album", It.IsAny<int?>(), "Some Artist", It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryAutoResolveAlbumAsync_PassesTheArtistThroughToTheDiscogsSearch()
    {
        // regression: a common album title without an artist hint returns many unrelated candidates - the
        // artist must reach IDiscogsClient.SearchAlbumsAsync, not just get dropped along the way.
        var discogsClient = FakeDiscogsClient.WithSearchResults(new DiscogsSearchResult("1", "Some Album", 2020, "Pink Floyd", null));
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Pink Floyd", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) =>
        {
            m.Id ??= "generated-id";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        await service.TryAutoResolveAlbumAsync("The Dark Side of the Moon", 1973, "Pink Floyd");

        discogsClient.LastSearchArtist.Should().Be("Pink Floyd");
    }

    [Fact]
    public async Task ResolveAlbumAsync_PropagatesTheUpsertedReferenceId()
    {
        var discogsClient = FakeDiscogsClient.Empty();
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Some Artist", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) =>
        {
            m.Id = "reference-1";
            return m;
        });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        var result = await service.ResolveAlbumAsync("Some Album", 2020, "1");

        result.Id.Should().Be("reference-1");
        result.ArtistReferenceId.Should().Be("person-1");
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, "reference-1", "Some Album", It.IsAny<int?>(), "Some Artist", It.IsAny<string?>(), It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_LinksAndUpdatesTitleAndArtist_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel
        {
            Id = "album-1",
            OwnerId = "owner",
            Title = "Some Typo'd Album",
            Artist = "Wrong Artist",
            Year = 2020
        };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Album", 2020, "Wrong Artist"))
            .ReturnsAsync(new AlbumReferenceModel
            {
                Id = "reference-1",
                Title = "Some Album",
                TitleNormalized = "some album",
                ArtistReferenceId = "person-1",
                ExternalIds = []
            });
        _personReferenceRepository
            .Setup(r => r.FindByIdAsync("person-1"))
            .ReturnsAsync(new PersonReferenceModel { Id = "person-1", Name = "Correct Artist", ExternalIds = new Dictionary<string, string> { ["discogs"] = "100" } });

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
        result.Title.Should().Be("Some Album");
        result.Artist.Should().Be("Correct Artist");
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.ReferenceId == "reference-1"), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel
        {
            Id = "album-1",
            OwnerId = "owner",
            Title = "Some Album",
            Artist = "Some Artist",
            Year = 2019
        };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Album", 2019, "Some Artist"))
            .ReturnsAsync(new AlbumReferenceModel
            {
                Id = "reference-1",
                Title = "Some Album",
                TitleNormalized = "some album",
                Year = 2020,
                ExternalIds = []
            });

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.Year.Should().Be(2020);
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.Year == 2020), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_SetsGenreFromTheReferencesGenres_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel
        {
            Id = "album-1",
            OwnerId = "owner",
            Title = "Some Album",
            Artist = "Some Artist",
            Year = 2020
        };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Album", 2020, "Some Artist"))
            .ReturnsAsync(new AlbumReferenceModel
            {
                Id = "reference-1",
                Title = "Some Album",
                TitleNormalized = "some album",
                ExternalIds = [],
                Genres = ["Pop", "K-pop"]
            });

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.Genre.Should().Be("Pop, K-pop");
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.Genre == "Pop, K-pop"), "owner"), Times.Once);
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, "reference-1", "Some Album", It.IsAny<int?>(), It.IsAny<string?>(), "Pop, K-pop", It.IsAny<double?>(), It.IsAny<double?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel
        {
            Id = "album-1",
            OwnerId = "owner",
            Title = "Some Album",
            Artist = "Some Artist",
            Year = 2020,
            ReferenceId = "old-reference"
        };
        _albumReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Album", 2020, "Some Artist")).ReturnsAsync((AlbumReferenceModel?)null);
        _albumReferenceRepository.Setup(r => r.FindByTitleAsync("Some Album", "Some Artist")).ReturnsAsync((AlbumReferenceModel?)null);

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
    }

    [Fact]
    public async Task RefreshAlbumReferenceAsync_ReturnsUnchanged_WhenReferenceHasNoExternalId()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var reference = new AlbumReferenceModel { Id = "reference-1", Title = "Some Album", TitleNormalized = "some album", ExternalIds = [] };

        var (result, changed) = await service.RefreshAlbumReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.Should().BeSameAs(reference);
        _albumReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>()), Times.Never);
    }

    [Fact]
    public async Task RefreshAlbumReferenceAsync_AlwaysRefetches_RegardlessOfLastEnrichedAt()
    {
        // Discogs exposes no "changed since" endpoint (unlike TMDB) - every refresh call does a full
        // re-fetch, even when LastEnrichedAt is very recent.
        var discogsClient = FakeDiscogsClient.Empty();
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album - Updated", 2020, "New synopsis", "Some Artist", "100", ["Rock"], null,
            [new DiscogsTrack("1", "Intro", "0:22"), new DiscogsTrack("2", "Apocalypse Please", "4:12")]);
        var reference = new AlbumReferenceModel
        {
            Id = "reference-1",
            Title = "Some Album",
            TitleNormalized = "some album",
            ExternalIds = new Dictionary<string, string> { ["discogs"] = "1" },
            LastEnrichedAt = DateTime.UtcNow
        };
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) => m);
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) =>
        {
            m.Id ??= "person-1";
            return m;
        });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        var (result, changed) = await service.RefreshAlbumReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Album - Updated");
        result.Genres.Should().Contain("Rock");
        result.Tracks.Should().SatisfyRespectively(
            t =>
            {
                t.Position.Should().Be("1");
                t.Title.Should().Be("Intro");
                t.Duration.Should().Be("0:22");
            },
            t =>
            {
                t.Position.Should().Be("2");
                t.Title.Should().Be("Apocalypse Please");
                t.Duration.Should().Be("4:12");
            });
    }

    /// <summary>
    /// Every provider client is a strict mock with zero setups: any provider call at all fails the test.
    /// This is exactly what the empty-title guards promise - a null/empty/whitespace title must never
    /// reach an external provider (or unlink anything) in any of the five domains.
    /// </summary>
    private ReferenceEnrichmentService CreateServiceWithStrictClients() => new(
        new Mock<ITmdbClient>(MockBehavior.Strict).Object,
        new Mock<IOmdbClient>(MockBehavior.Strict).Object,
        _omdbCallBudget,
        new ReferenceClientRegistry<IBookReferenceClient>([new Mock<IBookReferenceClient>(MockBehavior.Strict).Object], DefaultBookProvider),
        new Mock<IBookRatingByIsbnLookup>(MockBehavior.Strict).Object,
        StrictVideoGameRegistry,
        new Mock<IDiscogsClient>(MockBehavior.Strict).Object,
        _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
        _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
        _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object,
        _appSettingRepository.Object, new RatingSourceOptions(StrictVideoGameRegistry), NullLogger<ReferenceEnrichmentService>.Instance);

    /// <summary>
    /// A registry over a strict client mock. Held apart so the service and its RatingSourceOptions share one -
    /// resolving the default client is a property read, which a strict mock allows; it is the *calls* that must
    /// fail the test.
    /// </summary>
    private static ReferenceClientRegistry<IVideoGameReferenceClient> StrictVideoGameRegistry
    {
        get
        {
            var client = new Mock<IVideoGameReferenceClient>(MockBehavior.Strict);
            client.SetupGet(c => c.ProviderKey).Returns(RatingSourceCatalog.Igdb);
            client.SetupGet(c => c.SupportedRatingSources).Returns([RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic]);
            return new ReferenceClientRegistry<IVideoGameReferenceClient>([client.Object], RatingSourceCatalog.Igdb);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task TryAutoResolve_NeverCallsAProvider_OnAnEmptyTitle_ForAnyDomain(string title)
    {
        var service = CreateServiceWithStrictClients();

        await service.TryAutoResolveTvShowAsync(title, 2020);
        await service.TryAutoResolveMovieAsync(title, 2020);
        await service.TryAutoResolveBookAsync(title, 2020, "Some Author");
        await service.TryAutoResolveVideoGameAsync(title, 2020);
        await service.TryAutoResolveAlbumAsync(title, 2020, "Some Artist");

        // strict client mocks already fail on any provider call; the repositories must be equally untouched
        _tvShowRepository.VerifyNoOtherCalls();
        _movieRepository.VerifyNoOtherCalls();
        _bookRepository.VerifyNoOtherCalls();
        _videoGameRepository.VerifyNoOtherCalls();
        _albumRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task TryLinkExisting_LeavesAnExistingLinkUntouched_OnAnEmptyTitle_ForAnyDomain()
    {
        // without the guard, an empty title would match nothing and the "no match" branch would wrongly
        // clear ReferenceId - empty input must be a no-op, not an unlink
        var service = CreateServiceWithStrictClients();

        var show = await service.TryLinkExistingTvShowReferenceAsync(new TvShowModel { OwnerId = "o", Title = " ", ReferenceId = "ref-1" });
        var movie = await service.TryLinkExistingMovieReferenceAsync(new MovieModel { OwnerId = "o", Title = "", ReferenceId = "ref-1" });
        var book = await service.TryLinkExistingBookReferenceAsync(new BookModel { OwnerId = "o", Title = "", Author = "A", ReferenceId = "ref-1" });
        var game = await service.TryLinkExistingVideoGameReferenceAsync(new VideoGameModel { OwnerId = "o", Title = " ", ReferenceId = "ref-1" });
        var album = await service.TryLinkExistingAlbumReferenceAsync(new AlbumModel { OwnerId = "o", Title = "", Artist = "B", ReferenceId = "ref-1" });

        show.ReferenceId.Should().Be("ref-1");
        movie.ReferenceId.Should().Be("ref-1");
        book.ReferenceId.Should().Be("ref-1");
        game.ReferenceId.Should().Be("ref-1");
        album.ReferenceId.Should().Be("ref-1");
        _tvShowReferenceRepository.VerifyNoOtherCalls();
        _movieReferenceRepository.VerifyNoOtherCalls();
        _bookReferenceRepository.VerifyNoOtherCalls();
        _videoGameReferenceRepository.VerifyNoOtherCalls();
        _albumReferenceRepository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Resolve_Throws_OnAnEmptyTitle_ForAnyDomain()
    {
        // Resolve* is the admin's explicit link action - an empty title there is a caller bug and maps
        // to a 400 via ApiExceptionFilterAttribute rather than being silently ignored
        var service = CreateServiceWithStrictClients();

        await ((Func<Task>)(() => service.ResolveTvShowAsync("", 2020, "42"))).Should().ThrowAsync<ArgumentException>();
        await ((Func<Task>)(() => service.ResolveMovieAsync("", 2020, "42"))).Should().ThrowAsync<ArgumentException>();
        await ((Func<Task>)(() => service.ResolveBookAsync(" ", 2020, "42"))).Should().ThrowAsync<ArgumentException>();
        await ((Func<Task>)(() => service.ResolveVideoGameAsync("", 2020, "42"))).Should().ThrowAsync<ArgumentException>();
        await ((Func<Task>)(() => service.ResolveAlbumAsync(" ", 2020, "42"))).Should().ThrowAsync<ArgumentException>();
    }

    private sealed class FakeBookRatingByIsbnLookup : IBookRatingByIsbnLookup
    {
        /// <summary>Result the fallback returns; defaults to "no rating" so tests not exercising it are unaffected.</summary>
        public (double? Average, int? Count) Result { get; set; } = (null, null);

        /// <summary>When set, the lookup throws it instead of answering - Open Library timing out or 5xx-ing.</summary>
        public Exception? Failure { get; set; }

        public List<string> RequestedIsbns { get; } = [];

        public Task<(double? Average, int? Count)> GetRatingByIsbnAsync(string isbn, CancellationToken cancellationToken = default)
        {
            RequestedIsbns.Add(isbn);
            return Failure is not null ? Task.FromException<(double?, int?)>(Failure) : Task.FromResult(Result);
        }
    }

    private sealed class FakeTmdbClient : ITmdbClient
    {
        private readonly List<TmdbSearchResult> _tvShowSearchResults;

        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

        public Dictionary<string, TmdbMovieDetails> MovieDetails { get; } = new();

        public Dictionary<string, List<TmdbCastMember>> Cast { get; } = new();

        /// <summary>Whether TMDB reports a change for a given id - defaults to true (changed) when unset.</summary>
        public Dictionary<string, bool> ChangedSince { get; } = new();

        public List<string> TvShowDetailsRequested { get; } = [];

        public List<string> MovieDetailsRequested { get; } = [];

        public List<string> ChangesRequested { get; } = [];

        private FakeTmdbClient(List<TmdbSearchResult> tvShowSearchResults) => _tvShowSearchResults = tvShowSearchResults;

        public static FakeTmdbClient WithTvShowSearchResults(params TmdbSearchResult[] results) => new([.. results]);

        public Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedMoviesAsync(int page, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbTopRatedItem>>([]);

        public Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedTvShowsAsync(int page, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbTopRatedItem>>([]);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>(_tvShowSearchResults);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>([]);

        public Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            TvShowDetailsRequested.Add(tmdbId);
            return Task.FromResult(TvShowDetails.GetValueOrDefault(tmdbId));
        }

        public Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            MovieDetailsRequested.Add(tmdbId);
            return Task.FromResult(MovieDetails.GetValueOrDefault(tmdbId));
        }

        public Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>(Cast.GetValueOrDefault(tmdbId) ?? []);

        public Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbCastMember>>(Cast.GetValueOrDefault(tmdbId) ?? []);

        public Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default)
        {
            ChangesRequested.Add(tmdbId);
            return Task.FromResult(ChangedSince.GetValueOrDefault(tmdbId, true));
        }

        public Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default)
        {
            ChangesRequested.Add(tmdbId);
            return Task.FromResult(ChangedSince.GetValueOrDefault(tmdbId, true));
        }

        /// <summary>imdb id served by the cheap external-ids lookup - keyed by tmdb id, defaults to null (unknown).</summary>
        public Dictionary<string, string?> ImdbIds { get; } = new();

        public List<string> ImdbIdsRequested { get; } = [];

        public Task<string?> GetTvShowImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            ImdbIdsRequested.Add(tmdbId);
            return Task.FromResult(ImdbIds.GetValueOrDefault(tmdbId));
        }

        public Task<string?> GetMovieImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            ImdbIdsRequested.Add(tmdbId);
            return Task.FromResult(ImdbIds.GetValueOrDefault(tmdbId));
        }
    }
}
