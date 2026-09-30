using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises POST /api/tv-shows/{id}/refresh-reference and /api/movies/{id}/refresh-reference - the
/// user-triggered, exact-match-only re-check against the local reference collection. Deliberately not
/// admin-gated (unlike the TMDB search/link endpoints), so the standard test user can call it directly.
/// </summary>
public class RefreshReferenceResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task RefreshReference_LinksTvShow_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Refresh Reference Test Show {Guid.NewGuid()}";
        // unique per test, like the searched title: creating the show links it in the background, which rewrites its title to the canonical one, so the refresh below looks the *canonical* title up.
        // A canonical title two tests share would let that lookup answer with the other test's document.
        var canonicalTitle = $"Canonical Refresh Show {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new TvShowReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            // both aliases a real resolve records: the canonical (title, year) and whatever the tenant searched with (see MatchedAliases / ReferenceAliasRule)
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("tvshow_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = title, Year = year });

        var refreshed = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().Be(reference.Id);
        refreshed.Title.Should().Be(canonicalTitle);
    }

    [Fact]
    public async Task RefreshReference_LeavesTvShowUnresolved_WhenNoMatchingReferenceExists()
    {
        await Authenticate();
        var title = $"Refresh Reference No Match {Guid.NewGuid()}";
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = title, Year = 2019 });

        var refreshed = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().BeNullOrEmpty();
    }

    [Fact]
    public async Task RefreshReference_LinksMovie_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Refresh Reference Test Movie {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Refresh Movie {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("movie_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/movies", new MovieDto { Title = title, Year = year });

        var refreshed = await PostAsync<MovieDto?>($"/api/movies/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().Be(reference.Id);
        refreshed.Title.Should().Be(canonicalTitle);
    }

    [Fact]
    public async Task RefreshReference_LinksBook_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Refresh Reference Test Book {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Refresh Book {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new BookReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            // book/album aliases also carry the normalized creator - it is part of the identity here, and a creator-less alias is refused outright (see ReferenceAliasRule), which is why the canonical one has to be seeded rather than left to the repository
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year, Creator = TitleNormalizer.Normalize("Some Author") },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year, Creator = TitleNormalizer.Normalize("Some Author") }
            ]
        });
        TrackDocument("book_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/books", new BookDto { Title = title, Author = "Some Author", Year = year });

        var refreshed = await PostAsync<BookDto?>($"/api/books/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().Be(reference.Id);
        refreshed.Title.Should().Be(canonicalTitle);
    }

    [Fact]
    public async Task RefreshReference_LinksVideoGame_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Refresh Reference Test Game {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Refresh Game {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("videogame_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/video-games", new VideoGameDto { Title = title, Year = year });

        var refreshed = await PostAsync<VideoGameDto?>($"/api/video-games/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().Be(reference.Id);
        refreshed.Title.Should().Be(canonicalTitle);
    }

    [Fact]
    public async Task RefreshReference_LinksAlbum_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Refresh Reference Test Album {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Refresh Album {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new AlbumReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            // an album alias carries no year at all - title + artist is the identity (see ReferenceAliasRule)
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Creator = TitleNormalizer.Normalize("Some Artist") },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Creator = TitleNormalizer.Normalize("Some Artist") }
            ]
        });
        TrackDocument("album_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/albums", new AlbumDto { Title = title, Artist = "Some Artist", Year = year });

        var refreshed = await PostAsync<AlbumDto?>($"/api/albums/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        refreshed!.ReferenceId.Should().Be(reference.Id);
        refreshed.Title.Should().Be(canonicalTitle);
    }

    /// <summary>
    /// The create journey, end to end: adding a game whose title and year identify exactly one game must link
    /// it without anyone clicking anything. Reported from the running app with "code vein season pass" (2019).
    /// <para>
    /// The title is deliberately typed the way a person types it - <b>no colon</b>, where IGDB spells it
    /// "Code Vein: Season Pass". That difference is not cosmetic: it makes the exact-name query return nothing
    /// at all, so this only works if the relevance rung is asked too and the confirmation is loose about
    /// punctuation. Every unit test in this area feeds candidates in directly and therefore cannot catch a
    /// break in that wiring.
    /// </para>
    /// <para>
    /// <c>OnCreatedAsync</c> resolves on a detached background task, so this polls rather than asserting once.
    /// </para>
    /// </summary>
    /// <summary>
    /// Both titles reach the same rule by different routes, which is why both are here.
    /// "code vein season pass" is spelled differently from IGDB's own "Code Vein: Season Pass", so it is found only by the relevance rung and confirmed only because punctuation is folded.
    /// "Resident Evil 2" is one of eight games IGDB holds under exactly that name, so it is found by the exact-name rung and narrowed only by the year.
    /// </summary>
    [Theory]
    [InlineData("code vein season pass", 2019)]
    [InlineData("Resident Evil 2", 2019)]
    public async Task CreatingAVideoGame_LinksItAutomatically_WhenTitleAndYearIdentifyExactlyOneGame(string title, int year)
    {
        await Authenticate();
        await RequireNoLocalReferenceAsync(title, year);
        var created = await CreateAsync("/api/video-games", new VideoGameDto { Title = title, Year = year });

        var linked = await PollForReferenceLinkAsync($"/api/video-games/{created.Id}");

        TrackReference(linked);
        linked.Should().NotBeNullOrEmpty("IGDB identifies exactly one game as \"{0}\" ({1}), so nothing is being guessed at", title, year);
    }

    /// <summary>
    /// Polls a just-created item until its background reference resolution lands, or gives up. The resolve
    /// makes a provider call or two, so the budget is generous; returning empty is a real answer here (the
    /// caller asserts on it) rather than a timeout to throw on.
    /// </summary>
    private async Task<string?> PollForReferenceLinkAsync(string url)
    {
        for (var attempt = 0; attempt < 30; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
            var item = await GetAsync<VideoGameDto>(url);
            if (!string.IsNullOrEmpty(item.ReferenceId)) return item.ReferenceId;
        }

        return null;
    }

    /// <summary>
    /// Both video game cases below prove that a title+year reaches the <b>provider</b>, so both are only
    /// meaningful while no local reference already answers - and each one *creates* exactly such a reference by
    /// passing. Left behind, they would make their own next run (and each other) pass through the cheap local
    /// path instead, still green and no longer testing anything. This is the deliberate exception to "reference
    /// documents from a real provider are left in place": here their absence is the premise.
    /// </summary>
    private void TrackReference(string? referenceId)
    {
        if (!string.IsNullOrEmpty(referenceId)) TrackDocument("videogame_reference", referenceId);
    }

    /// <summary>
    /// Fails loudly and by name when a leftover reference would make the test pass for the wrong reason,
    /// rather than letting it go quietly green - the same "check the premise and say what broke it" shape
    /// <c>ExploreSmokeTest</c> uses.
    /// </summary>
    private async Task RequireNoLocalReferenceAsync(string title, int year)
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var existing = await repository.FindByTitleYearAsync(title, year);

        existing.Should().BeNull(
            "this case proves the provider is reached, which is only observable while nothing local answers - " +
            "a leftover \"{0}\" ({1}) reference means an earlier run did not clean up after itself", title, year);
    }

    /// <summary>
    /// The journey the detail page's button actually promises: <i>"Not right? Edit the title or year below,
    /// then check again."</i>
    /// <para>
    /// A tenant with a real title and a real year, and <b>no reference document anywhere yet</b>, must end up
    /// linked. This is the ordinary state for anything created before its year was known - automatic
    /// resolution runs only on create, refuses to guess without a year, and so writes no reference at all;
    /// from then on the local-only re-check can never find one however correct the title and year become.
    /// Reported from the running app with "Code Vein: Season Pass" (2019), which IGDB holds exactly once.
    /// </para>
    /// <para>
    /// Real IGDB, deliberately: the whole point is that nothing local can answer this, and a fake provider
    /// would prove only that the plumbing compiles. Skips rather than fails on a 502 - see
    /// <see cref="ResourceTestBase.GetThroughLiveProviderAsync{T}"/>.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RefreshReference_LinksVideoGameThroughTheProvider_WhenNoReferenceExistsYetAndTitleAndYearMatchExactly()
    {
        // a different game from the create case above, so neither can supply the other's reference and make it
        // pass through the local path
        await Authenticate();
        await RequireNoLocalReferenceAsync("Code Vein: Frozen Empress", 2020);
        // created without a year and given one afterwards - the exact journey that reaches this button, and
        // the one that leaves no reference behind for the local lookup to find (resolution on create correctly
        // refuses to choose between same-titled games without a year)
        var created = await CreateAsync("/api/video-games", new VideoGameDto { Title = "Code Vein: Frozen Empress" });
        created.Year = 2020;
        await PutAsync($"/api/video-games/{created.Id}", created);

        var refreshed = await PostThroughLiveProviderAsync<VideoGameDto?>($"/api/video-games/{created.Id}/refresh-reference", "IGDB");

        TrackReference(refreshed!.ReferenceId);
        refreshed.ReferenceId.Should().NotBeNullOrEmpty("IGDB holds exactly one game called \"Code Vein: Frozen Empress\" (2020)");
    }

    /// <summary>
    /// The rule the provider escalation must not break: with no year and several games sharing the title,
    /// there is nothing to choose with, so nothing is chosen. "Resident Evil 2" is eight games on IGDB.
    /// </summary>
    [Fact]
    public async Task RefreshReference_LeavesVideoGameUnresolved_WhenNoYearIsGivenAndSeveralGamesShareTheTitle()
    {
        await Authenticate();
        var created = await CreateAsync("/api/video-games", new VideoGameDto { Title = "Resident Evil 2" });

        var refreshed = await PostThroughLiveProviderAsync<VideoGameDto?>($"/api/video-games/{created.Id}/refresh-reference", "IGDB");

        refreshed!.ReferenceId.Should().BeNullOrEmpty("nothing but the year separates IGDB's eight \"Resident Evil 2\" entries");
    }
}
