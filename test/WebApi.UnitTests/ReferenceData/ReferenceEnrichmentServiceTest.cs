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

    /// <summary>
    /// The registry always has "openlibrary" as the deployment default - matches FakeBookReferenceClient's
    /// hardcoded ProviderKey, so every existing test that never mentions a provider keeps resolving the
    /// same fake it always did.
    /// </summary>
    private const string DefaultBookProvider = "openlibrary";

    private ReferenceEnrichmentService CreateService(
        FakeTmdbClient tmdbClient,
        FakeBookReferenceClient? bookReferenceClient = null,
        FakeRawgClient? rawgClient = null,
        FakeDiscogsClient? discogsClient = null,
        FakeBnfClient? bnfClient = null) => new(
        tmdbClient,
        new BookReferenceClientRegistry([bookReferenceClient ?? FakeBookReferenceClient.Empty(), bnfClient ?? FakeBnfClient.Empty()], DefaultBookProvider),
        rawgClient ?? FakeRawgClient.Empty(), discogsClient ?? FakeDiscogsClient.Empty(),
        _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
        _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
        _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object);

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchReturnsNoResults()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(
            new TmdbSearchResult("1", "Some Show", 2020, null, null),
            new TmdbSearchResult("2", "Some Show", 2020, null, null)));

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveTvShowAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults(new TmdbSearchResult("42", "Some Show", 2020, "Synopsis", null));
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        var service = CreateService(tmdbClient);

        await service.TryAutoResolveTvShowAsync("Some Show", 2020);

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(m => m.ExternalIds["tmdb"] == "42")), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, It.IsAny<string>(), "Some Show", It.IsAny<int?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveTvShowAsync_PropagatesTheUpsertedReferenceId()
    {
        var tmdbClient = FakeTmdbClient.WithTvShowSearchResults();
        tmdbClient.TvShowDetails["42"] = new TmdbTvShowDetails("42", "Some Show", 2020, "Synopsis", [], [], null);
        _tvShowReferenceRepository
            .Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>()))
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id = "reference-1"; return m; });
        var service = CreateService(tmdbClient);

        var result = await service.ResolveTvShowAsync("Some Show", 2020, "42");

        result.Id.Should().Be("reference-1");
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2020, "reference-1", "Some Show", It.IsAny<int?>()), Times.Once);
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
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "reference-1"; return m; });
        var service = CreateService(tmdbClient);

        // the tenant searched with a different-language title than TMDB's canonical English one
        await service.ResolveTvShowAsync("Le Fil", 2002, "42");

        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(
            m => m.MatchedAliases.Any(a => a.Title == "the wire" && a.Year == 2002)
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
        _tvShowReferenceRepository.Verify(r => r.UpsertAsync(It.Is<TvShowReferenceModel>(
            m => m.MatchedAliases.Any(a => a.Title == "the wire" && a.Year == 2002)
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
            .ReturnsAsync((TvShowReferenceModel m) => { m.Id ??= "reference-1"; return m; });
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
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "A Different Show", Year = 2021, ReferenceId = "old-reference" };
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
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 2020, ReferenceId = "old-reference" };
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
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = null, ReferenceId = "reference-1" };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", null)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Some Show"))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", Year = 2020, ExternalIds = [] });

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
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Show", 2020, "reference-1", "Some Show", It.IsAny<int?>()), Times.Once);
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
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", Year = 2020, ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.Year.Should().Be(2020);
        _tvShowRepository.Verify(r => r.UpdateAsync("show-1", It.Is<TvShowModel>(m => m.Year == 2020), "owner"), Times.Once);
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync("Some Show", 2019, "reference-1", "Some Show", 2020), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingTvShowReferenceAsync_FallsBackToTitleOnlyMatch_WhenTitleYearMatchMisses()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new TvShowModel { Id = "show-1", OwnerId = "owner", Title = "Some Show", Year = 1999 };
        _tvShowReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Show", 1999)).ReturnsAsync((TvShowReferenceModel?)null);
        _tvShowReferenceRepository
            .Setup(r => r.FindByTitleAsync("Some Show"))
            .ReturnsAsync(new TvShowReferenceModel { Id = "reference-1", Title = "Some Show", TitleNormalized = "some show", ExternalIds = [] });

        var result = await service.TryLinkExistingTvShowReferenceAsync(model);

        result.ReferenceId.Should().Be("reference-1");
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
        _tvShowRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
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
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Typo'd Movie", 2020, "reference-1", "Some Movie", It.IsAny<int?>()), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_UpdatesYearToTheReferencesCanonicalYear_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Movie", Year = 2019 };
        _movieReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Movie", 2019))
            .ReturnsAsync(new MovieReferenceModel { Id = "reference-1", Title = "Some Movie", TitleNormalized = "some movie", Year = 2020, ExternalIds = [] });

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.Year.Should().Be(2020);
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.Year == 2020), "owner"), Times.Once);
        _movieRepository.Verify(r => r.SetReferenceLinkAsync("Some Movie", 2019, "reference-1", "Some Movie", 2020), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingMovieReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new MovieModel { Id = "movie-1", OwnerId = "owner", Title = "Some Movie", Year = 2020, ReferenceId = "old-reference" };
        _movieReferenceRepository.Setup(r => r.FindByTitleYearAsync("Some Movie", 2020)).ReturnsAsync((MovieReferenceModel?)null);
        _movieReferenceRepository.Setup(r => r.FindByTitleAsync("Some Movie")).ReturnsAsync((MovieReferenceModel?)null);

        var result = await service.TryLinkExistingMovieReferenceAsync(model);

        result.ReferenceId.Should().BeEmpty();
        _movieRepository.Verify(r => r.UpdateAsync("movie-1", It.Is<MovieModel>(m => m.ReferenceId == string.Empty), "owner"), Times.Once);
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

        _bookRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveBookAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var bookReferenceClient = FakeBookReferenceClient.WithSearchResults(new BookSearchResult("OL1W", "Some Book", 2020, "Some Author", null));
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.TryAutoResolveBookAsync("Some Book", 2020);

        _bookReferenceRepository.Verify(r => r.UpsertAsync(It.Is<BookReferenceModel>(m => m.ExternalIds["openlibrary"] == "OL1W")), Times.Once);
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, It.IsAny<string>(), "Some Book", It.IsAny<int?>(), "Some Author"), Times.Once);
    }

    [Fact]
    public async Task TryAutoResolveBookAsync_PassesTheAuthorThroughToTheBookSearch()
    {
        // regression: a common title without an author hint returns many unrelated candidates - the
        // author must reach IBookReferenceClient.SearchBooksAsync, not just get dropped along the way.
        var bookReferenceClient = FakeBookReferenceClient.WithSearchResults(new BookSearchResult("OL1W", "Some Book", 2020, "Lee Child", null));
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Lee Child", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        await service.TryAutoResolveBookAsync("Killing Floor", 2016, "Lee Child");

        bookReferenceClient.LastSearchAuthor.Should().Be("Lee Child");
    }

    [Fact]
    public async Task ResolveBookAsync_PropagatesTheUpsertedReferenceId()
    {
        var bookReferenceClient = FakeBookReferenceClient.Empty();
        bookReferenceClient.Details["OL1W"] = new BookDetails("OL1W", "Some Book", 2020, "Synopsis", "Some Author", "OL1A", [], null);
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id = "reference-1"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "OL1W");

        result.Id.Should().Be("reference-1");
        result.AuthorReferenceId.Should().Be("person-1");
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, "reference-1", "Some Book", It.IsAny<int?>(), "Some Author"), Times.Once);
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
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id = "reference-1"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
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
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id = "reference-1"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "OL1W");

        result.Isbn.Should().BeNull();
        result.MatchedAliases.Should().OnlyContain(a => a.Isbn == null);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_LinksAndUpdatesTitleAndAuthor_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel { Id = "book-1", OwnerId = "owner", Title = "Some Typo'd Book", Author = "Wrong Author", Year = 2020 };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Book", 2020, "Wrong Author"))
            .ReturnsAsync(new BookReferenceModel { Id = "reference-1", Title = "Some Book", TitleNormalized = "some book", AuthorReferenceId = "person-1", ExternalIds = [] });
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
        var model = new BookModel { Id = "book-1", OwnerId = "owner", Title = "Some Book", Author = "Some Author", Year = 2019 };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Book", 2019, "Some Author"))
            .ReturnsAsync(new BookReferenceModel { Id = "reference-1", Title = "Some Book", TitleNormalized = "some book", Year = 2020, ExternalIds = [] });

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.Year.Should().Be(2020);
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.Year == 2020), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_SetsGenreFromTheReferencesGenres_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel { Id = "book-1", OwnerId = "owner", Title = "Some Book", Author = "Some Author", Year = 2020 };
        _bookReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Book", 2020, "Some Author"))
            .ReturnsAsync(new BookReferenceModel { Id = "reference-1", Title = "Some Book", TitleNormalized = "some book", ExternalIds = [], Genres = ["Thriller", "Mystery"] });

        var result = await service.TryLinkExistingBookReferenceAsync(model);

        result.Genre.Should().Be("Thriller, Mystery");
        _bookRepository.Verify(r => r.UpdateAsync("book-1", It.Is<BookModel>(m => m.Genre == "Thriller, Mystery"), "owner"), Times.Once);
        _bookRepository.Verify(r => r.SetReferenceLinkAsync("Some Book", 2020, "reference-1", "Some Book", It.IsAny<int?>(), It.IsAny<string?>(), "Thriller, Mystery"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingBookReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new BookModel { Id = "book-1", OwnerId = "owner", Title = "Some Book", Author = "Some Author", Year = 2020, ReferenceId = "old-reference" };
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
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bookReferenceClient);

        var (result, changed) = await service.RefreshBookReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Book - Updated");
        result.Genres.Should().Contain("Fiction");
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
        _bookReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => { m.Id = "reference-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), bnfClient: bnfClient);

        var result = await service.ResolveBookAsync("Some Book", 2020, "ark:/12148/cb1", "bnf");

        result.ExternalIds["bnf"].Should().Be("ark:/12148/cb1");
        result.ExternalIds.Should().NotContainKey("openlibrary");
        result.Language.Should().Be("fre");
    }

    [Fact]
    public async Task TryAutoResolveVideoGameAsync_DoesNothing_WhenSearchIsAmbiguous()
    {
        var rawgClient = FakeRawgClient.WithSearchResults(
            new RawgSearchResult("1", "Some Game", 2020, null),
            new RawgSearchResult("2", "Some Game", 2020, null));
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), rawgClient: rawgClient);

        await service.TryAutoResolveVideoGameAsync("Some Game", 2020);

        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveVideoGameAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var rawgClient = FakeRawgClient.WithSearchResults(new RawgSearchResult("1", "Some Game", 2020, null));
        rawgClient.Details["1"] = new RawgGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), rawgClient: rawgClient);

        await service.TryAutoResolveVideoGameAsync("Some Game", 2020);

        _videoGameReferenceRepository.Verify(r => r.UpsertAsync(It.Is<VideoGameReferenceModel>(m => m.ExternalIds["rawg"] == "1")), Times.Once);
        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync("Some Game", 2020, It.IsAny<string>(), "Some Game", It.IsAny<int?>()), Times.Once);
    }

    [Fact]
    public async Task ResolveVideoGameAsync_PropagatesTheUpsertedReferenceId()
    {
        var rawgClient = FakeRawgClient.Empty();
        rawgClient.Details["1"] = new RawgGameDetails("1", "Some Game", 2020, "Synopsis", [], [], null);
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => { m.Id = "reference-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), rawgClient: rawgClient);

        var result = await service.ResolveVideoGameAsync("Some Game", 2020, "1");

        result.Id.Should().Be("reference-1");
        _videoGameRepository.Verify(r => r.SetReferenceLinkAsync("Some Game", 2020, "reference-1", "Some Game", It.IsAny<int?>()), Times.Once);
    }

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
            .ReturnsAsync(new VideoGameReferenceModel { Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", Year = 2020, ExternalIds = [] });

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
    public async Task RefreshVideoGameReferenceAsync_ReturnsUnchanged_WhenReferenceHasNoExternalId()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var reference = new VideoGameReferenceModel { Id = "reference-1", Title = "Some Game", TitleNormalized = "some game", ExternalIds = [] };

        var (result, changed) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeFalse();
        result.Should().BeSameAs(reference);
        _videoGameReferenceRepository.Verify(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>()), Times.Never);
    }

    [Fact]
    public async Task RefreshVideoGameReferenceAsync_AlwaysRefetches_RegardlessOfLastEnrichedAt()
    {
        // RAWG exposes no "changed since" endpoint (unlike TMDB) - every refresh call does a full
        // re-fetch, even when LastEnrichedAt is very recent.
        var rawgClient = FakeRawgClient.Empty();
        rawgClient.Details["1"] = new RawgGameDetails("1", "Some Game - Updated", 2020, "New synopsis", ["Action"], ["PC"], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" },
            LastEnrichedAt = DateTime.UtcNow
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), rawgClient: rawgClient);

        var (result, changed) = await service.RefreshVideoGameReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Game - Updated");
        result.Platforms.Should().Contain("PC");
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
        var rawgClient = FakeRawgClient.Empty();
        rawgClient.Details["1"] = new RawgGameDetails("1", "Some Game", 2020, "Synopsis", ["Action"], ["PC"], null);
        var reference = new VideoGameReferenceModel
        {
            Id = "reference-1",
            Title = "Some Game",
            TitleNormalized = "some game",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = "some game", Year = 2020, Creator = null }]
        };
        _videoGameReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), rawgClient: rawgClient);

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

        _albumRepository.Verify(r => r.SetReferenceLinkAsync(It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task TryAutoResolveAlbumAsync_ResolvesAndPropagates_WhenExactlyOneCandidate()
    {
        var discogsClient = FakeDiscogsClient.WithSearchResults(new DiscogsSearchResult("1", "Some Album", 2020, "Some Artist", null));
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Some Artist", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        await service.TryAutoResolveAlbumAsync("Some Album", 2020);

        _albumReferenceRepository.Verify(r => r.UpsertAsync(It.Is<AlbumReferenceModel>(m => m.ExternalIds["discogs"] == "1")), Times.Once);
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, It.IsAny<string>(), "Some Album", It.IsAny<int?>(), "Some Artist"), Times.Once);
    }

    [Fact]
    public async Task TryAutoResolveAlbumAsync_PassesTheArtistThroughToTheDiscogsSearch()
    {
        // regression: a common album title without an artist hint returns many unrelated candidates - the
        // artist must reach IDiscogsClient.SearchAlbumsAsync, not just get dropped along the way.
        var discogsClient = FakeDiscogsClient.WithSearchResults(new DiscogsSearchResult("1", "Some Album", 2020, "Pink Floyd", null));
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Pink Floyd", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) => { m.Id ??= "generated-id"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        await service.TryAutoResolveAlbumAsync("The Dark Side of the Moon", 1973, "Pink Floyd");

        discogsClient.LastSearchArtist.Should().Be("Pink Floyd");
    }

    [Fact]
    public async Task ResolveAlbumAsync_PropagatesTheUpsertedReferenceId()
    {
        var discogsClient = FakeDiscogsClient.Empty();
        discogsClient.Details["1"] = new DiscogsAlbumDetails("1", "Some Album", 2020, "Synopsis", "Some Artist", "100", [], null, []);
        _albumReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) => { m.Id = "reference-1"; return m; });
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        var result = await service.ResolveAlbumAsync("Some Album", 2020, "1");

        result.Id.Should().Be("reference-1");
        result.ArtistReferenceId.Should().Be("person-1");
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, "reference-1", "Some Album", It.IsAny<int?>(), "Some Artist"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_LinksAndUpdatesTitleAndArtist_OnTitleYearMatch()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel { Id = "album-1", OwnerId = "owner", Title = "Some Typo'd Album", Artist = "Wrong Artist", Year = 2020 };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Typo'd Album", 2020, "Wrong Artist"))
            .ReturnsAsync(new AlbumReferenceModel { Id = "reference-1", Title = "Some Album", TitleNormalized = "some album", ArtistReferenceId = "person-1", ExternalIds = [] });
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
        var model = new AlbumModel { Id = "album-1", OwnerId = "owner", Title = "Some Album", Artist = "Some Artist", Year = 2019 };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Album", 2019, "Some Artist"))
            .ReturnsAsync(new AlbumReferenceModel { Id = "reference-1", Title = "Some Album", TitleNormalized = "some album", Year = 2020, ExternalIds = [] });

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.Year.Should().Be(2020);
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.Year == 2020), "owner"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_SetsGenreFromTheReferencesGenres_OnLink()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel { Id = "album-1", OwnerId = "owner", Title = "Some Album", Artist = "Some Artist", Year = 2020 };
        _albumReferenceRepository
            .Setup(r => r.FindByTitleYearAsync("Some Album", 2020, "Some Artist"))
            .ReturnsAsync(new AlbumReferenceModel { Id = "reference-1", Title = "Some Album", TitleNormalized = "some album", ExternalIds = [], Genres = ["Pop", "K-pop"] });

        var result = await service.TryLinkExistingAlbumReferenceAsync(model);

        result.Genre.Should().Be("Pop, K-pop");
        _albumRepository.Verify(r => r.UpdateAsync("album-1", It.Is<AlbumModel>(m => m.Genre == "Pop, K-pop"), "owner"), Times.Once);
        _albumRepository.Verify(r => r.SetReferenceLinkAsync("Some Album", 2020, "reference-1", "Some Album", It.IsAny<int?>(), It.IsAny<string?>(), "Pop, K-pop"), Times.Once);
    }

    [Fact]
    public async Task TryLinkExistingAlbumReferenceAsync_Unlinks_WhenAlreadyLinkedButNoMatchFoundForTheCurrentTitle()
    {
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults());
        var model = new AlbumModel { Id = "album-1", OwnerId = "owner", Title = "Some Album", Artist = "Some Artist", Year = 2020, ReferenceId = "old-reference" };
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
        _personReferenceRepository.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => { m.Id ??= "person-1"; return m; });
        var service = CreateService(FakeTmdbClient.WithTvShowSearchResults(), discogsClient: discogsClient);

        var (result, changed) = await service.RefreshAlbumReferenceAsync(reference, TestContext.Current.CancellationToken);

        changed.Should().BeTrue();
        result.Title.Should().Be("Some Album - Updated");
        result.Genres.Should().Contain("Rock");
        result.Tracks.Should().SatisfyRespectively(
            t => { t.Position.Should().Be("1"); t.Title.Should().Be("Intro"); t.Duration.Should().Be("0:22"); },
            t => { t.Position.Should().Be("2"); t.Title.Should().Be("Apocalypse Please"); t.Duration.Should().Be("4:12"); });
    }

    /// <summary>
    /// Every provider client is a strict mock with zero setups: any provider call at all fails the test.
    /// This is exactly what the empty-title guards promise - a null/empty/whitespace title must never
    /// reach an external provider (or unlink anything) in any of the five domains.
    /// </summary>
    private ReferenceEnrichmentService CreateServiceWithStrictClients() => new(
        new Mock<ITmdbClient>(MockBehavior.Strict).Object,
        new BookReferenceClientRegistry([new Mock<IBookReferenceClient>(MockBehavior.Strict).Object], DefaultBookProvider),
        new Mock<IRawgClient>(MockBehavior.Strict).Object,
        new Mock<IDiscogsClient>(MockBehavior.Strict).Object,
        _tvShowReferenceRepository.Object, _movieReferenceRepository.Object, _personReferenceRepository.Object,
        _bookReferenceRepository.Object, _videoGameReferenceRepository.Object, _albumReferenceRepository.Object,
        _tvShowRepository.Object, _movieRepository.Object, _bookRepository.Object, _videoGameRepository.Object, _albumRepository.Object);

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

    private sealed class FakeTmdbClient : ITmdbClient
    {
        private readonly List<TmdbSearchResult> _tvShowSearchResults;

        public Dictionary<string, TmdbTvShowDetails> TvShowDetails { get; } = new();

        public Dictionary<string, TmdbMovieDetails> MovieDetails { get; } = new();

        public Dictionary<string, List<TmdbCastMember>> Cast { get; } = new();

        /// <summary>Whether TMDB reports a change for a given id - defaults to true (changed) when unset.</summary>
        public Dictionary<string, bool> ChangedSince { get; } = new();

        public List<string> TvShowDetailsRequested { get; } = [];

        public List<string> ChangesRequested { get; } = [];

        private FakeTmdbClient(List<TmdbSearchResult> tvShowSearchResults) => _tvShowSearchResults = tvShowSearchResults;

        public static FakeTmdbClient WithTvShowSearchResults(params TmdbSearchResult[] results) => new([.. results]);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>(_tvShowSearchResults);

        public Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TmdbSearchResult>>([]);

        public Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
        {
            TvShowDetailsRequested.Add(tmdbId);
            return Task.FromResult(TvShowDetails.GetValueOrDefault(tmdbId));
        }

        public Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default) =>
            Task.FromResult(MovieDetails.GetValueOrDefault(tmdbId));

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
    }
}
