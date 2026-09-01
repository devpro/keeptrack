using System;
using System.Collections.Generic;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// The reference-matching journey a person actually walks for the four domains that are not video games, driven through the real UI against the real TMDB, Google Books and Discogs.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VideoGameReferenceMatchSmokeTest"/> covers the fifth, and exists for the reason this one does: every regression the owner reported in this area was in the journey rather than the rule, and a test that feeds candidates into the rule can see none of it.
/// These four had the same defects and were fixed in the same pass, so they get the same coverage rather than being trusted to a green unit suite.
/// </para>
/// <para>
/// Three things are pinned per domain, all the owner's rules.
/// An identity field is required for any automatic link - a year for a film or a show, a creator for a book or an album - and until it is supplied nothing is linked.
/// Editing a field never searches by itself: the button is the only thing that re-resolves.
/// And a link must be <i>cleared</i> when the title it was based on stops naming that work, because a link outliving its title renders a cover and a rating for something else with nothing saying so.
/// </para>
/// <para>
/// The titles are real and chosen to be unambiguous to a human while being exactly what the old rule got wrong: TMDB answers "The Bear" (2022) with eight results and "Heat" (1995) with fourteen, and Google Books answers "Dune" by Frank Herbert with hundreds of editions.
/// None is shared with another test class, since these tests need no local reference to exist and delete the ones they create.
/// </para>
/// </remarks>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ReferenceMatchSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    /// <summary>
    /// A show TMDB returns beside seven other results, so it only links once candidates are compared by name rather than counted.
    /// </summary>
    [Fact]
    public async Task ATvShow_LinksOnItsTitleAndYear_ThenClearsWhenTheTitleStopsNamingIt()
    {
        SkipIfReadOnly();
        var list = await OpenListAsync(home => home.OpenTvShowsAsync());
        await AddAsync(list, "The Bear", ("Year", "2022"));
        var (detail, id) = await OpenDetailAsync(new TvShowDetailPage(Page), "/api/tv-shows");

        var linked = await WaitForLinkAsync<TvShowDto>("/api/tv-shows", id);
        linked.Should().NotBeNullOrEmpty("TMDB holds exactly one show named \"The Bear\" (2022), among the eight results it returns for it");

        await AssertEditAloneChangesNothingAsync<TvShowDto>("/api/tv-shows", id, detail, "The Bear Unnameable", linked);

        await detail.ClickCheckReferenceMatchAsync();
        var cleared = await WaitForLinkAsync<TvShowDto>("/api/tv-shows", id, linked);
        cleared.Should().BeNullOrEmpty("no show is called \"The Bear Unnameable\", and a link outliving its title points at the wrong work");
    }

    /// <summary>
    /// The film equivalent, and the domain that looked healthy only because a long title happens to narrow TMDB's fuzzy search to one row.
    /// </summary>
    [Fact]
    public async Task AMovie_LinksOnItsTitleAndYear_ThenClearsWhenTheTitleStopsNamingIt()
    {
        SkipIfReadOnly();
        var list = await OpenListAsync(home => home.OpenMoviesAsync());
        await AddAsync(list, "Heat", ("Year", "1995"));
        var (detail, id) = await OpenDetailAsync(new MovieDetailPage(Page), "/api/movies");

        var linked = await WaitForLinkAsync<MovieDto>("/api/movies", id);
        linked.Should().NotBeNullOrEmpty("TMDB holds exactly one film named \"Heat\" (1995), among the fourteen results it returns for it");

        await AssertEditAloneChangesNothingAsync<MovieDto>("/api/movies", id, detail, "Heat Unnameable", linked);

        await detail.ClickCheckReferenceMatchAsync();
        var cleared = await WaitForLinkAsync<MovieDto>("/api/movies", id, linked);
        cleared.Should().BeNullOrEmpty("no film is called \"Heat Unnameable\"");
    }

    /// <summary>
    /// A film created before its year is known links nothing, and links as soon as the year is supplied and checked - the journey that has no local reference to fall back on, so it proves the button reaches TMDB.
    /// </summary>
    [Fact]
    public async Task AMovieCreatedWithoutAYear_LinksNothingUntilTheYearIsSuppliedAndChecked()
    {
        SkipIfReadOnly();
        var list = await OpenListAsync(home => home.OpenMoviesAsync());
        await AddAsync(list, "Blade Runner");
        var (detail, id) = await OpenDetailAsync(new MovieDetailPage(Page), "/api/movies");

        // Asserted with nothing waited for, and that is sound rather than lucky: with no year the server returns from resolution before asking TMDB anything, so no later moment can produce a different answer.
        (await ReadLinkAsync<MovieDto>("/api/movies", id)).Should().BeNullOrEmpty(
            "a year is required for any automatic link to a film, and TMDB holds a \"Blade Runner\" from 1982 and other works by that name");

        await DetailPageBase.SetFieldAsync(detail.YearInput, "1982");
        await detail.ClickCheckReferenceMatchAsync();

        var linked = await WaitForLinkAsync<MovieDto>("/api/movies", id);
        linked.Should().NotBeNullOrEmpty("TMDB holds exactly one \"Blade Runner\" (1982)");
    }

    /// <summary>
    /// A book, where the identity is the author rather than the year and hundreds of editions are one work - so this fails in the opposite direction from the domains above if the rules are confused.
    /// </summary>
    [Fact]
    public async Task ABook_LinksNothingWithoutAnAuthor_ThenLinksOnceTheAuthorIsSuppliedAndChecked()
    {
        SkipIfReadOnly();
        var list = await OpenListAsync(home => home.OpenBooksAsync());
        await AddAsync(list, "Dune");
        var (detail, id) = await OpenDetailAsync(new BookDetailPage(Page), "/api/books");

        (await ReadLinkAsync<BookDto>("/api/books", id)).Should().BeNullOrEmpty(
            "an author is what identifies a book, so a title alone links nothing");

        await DetailPageBase.SetFieldAsync(detail.AuthorInput, "Frank Herbert");
        await detail.ClickCheckReferenceMatchAsync();

        var linked = await WaitForLinkAsync<BookDto>("/api/books", id);
        linked.Should().NotBeNullOrEmpty(
            "every volume Google Books returns for \"Dune\" by Frank Herbert is an edition of one work, which is a match rather than an ambiguity");
    }

    /// <summary>
    /// An album, the other creator-identified domain, and the one whose provider filters hard on a year it is easy to record wrongly.
    /// </summary>
    [Fact]
    public async Task AnAlbum_LinksNothingWithoutAnArtist_ThenLinksOnceTheArtistIsSuppliedAndChecked()
    {
        SkipIfReadOnly();
        var list = await OpenListAsync(home => home.OpenAlbumsAsync());
        await AddAsync(list, "Kid A", ("Year", "2000"));
        var (detail, id) = await OpenDetailAsync(new AlbumDetailPage(Page), "/api/albums");

        (await ReadLinkAsync<AlbumDto>("/api/albums", id)).Should().BeNullOrEmpty(
            "an artist is what identifies an album, so a title and a year alone link nothing");

        await DetailPageBase.SetFieldAsync(detail.ArtistInput, "Radiohead");
        await detail.ClickCheckReferenceMatchAsync();

        var linked = await WaitForLinkAsync<AlbumDto>("/api/albums", id);
        linked.Should().NotBeNullOrEmpty("Discogs holds one master \"Kid A\" by Radiohead");
    }

    /// <summary>
    /// The step claimed in prose everywhere and easy to lose: editing a field must neither search by itself nor disturb the link.
    /// </summary>
    /// <remarks>
    /// Waits for the edit to reach the server rather than sleeping, so the assertion happens at a known point instead of a hoped-for one - a negative has nothing of its own to wait for.
    /// </remarks>
    private async Task AssertEditAloneChangesNothingAsync<TDto>(string route, string id, ReferenceableDetailPageBase detail, string newTitle, string? linked)
        where TDto : IReferenceLinkedDto
    {
        await DetailPageBase.SetFieldAsync(detail.TitleInput, newTitle);

        for (var attempt = 0; attempt < 30; attempt++)
        {
            var item = await Fixture.ApiHttpClient.GetFromJsonAsync<TDto>($"{route}/{id}", TestContext.Current.CancellationToken);
            if (TitleOf(item) == newTitle)
            {
                item!.ReferenceId.Should().Be(linked, "editing a title changes nothing until the user asks; the button is the only thing that re-resolves");
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
        }

        Assert.Fail("the title edit never reached the server, so nothing after this point would mean anything");
    }

    private static string? TitleOf(object? dto) => dto switch
    {
        TvShowDto show => show.Title,
        MovieDto movie => movie.Title,
        BookDto book => book.Title,
        AlbumDto album => album.Title,
        _ => null
    };

    private async Task<ListPage> OpenListAsync(Func<HomePage, Task<ListPage>> open) => await open(await new HomePage(Page).OpenAsync());

    /// <summary>Adds an item through the list's own Add form, which navigates to its detail page.</summary>
    private async Task AddAsync(ListPage list, string title, params (string Placeholder, string Value)[] fields)
    {
        await list.ClickAddAsync();
        await list.FillByPlaceholderAsync("Title", title);
        foreach (var (placeholder, value) in fields)
        {
            await list.FillByPlaceholderAsync(placeholder, value);
        }

        await list.SaveNewAsync();
    }

    /// <summary>
    /// Waits for the just-created item's detail page and returns it with the id its URL carries.
    /// </summary>
    /// <remarks>
    /// The id is read here rather than straight after saving, because the Add form navigates asynchronously: reading <c>Page.Url</c> before the detail page is ready yields the list' own address and every later API call 404s.
    /// </remarks>
    private async Task<(TPage Detail, string Id)> OpenDetailAsync<TPage>(TPage detail, string route)
        where TPage : DetailPageBase
    {
        await detail.WaitForReadyAsync();
        TrackOpenItem(route);
        return (detail, ExtractIdFromUrl(Page.Url));
    }

    /// <summary>
    /// Waits for the item's reference link to settle, optionally until it differs from <paramref name="previous"/>.
    /// </summary>
    /// <remarks>
    /// Resolution on create runs as a detached background task and the check button's own resolve propagates by identity rather than by id, so neither is observable the instant the UI returns.
    /// Books get the longest budget for a measured reason: resolving one runs Open Library's rating fallback, whose <c>search.json</c> is the slowest endpoint any provider here calls at 36-41s.
    /// Returning the value rather than asserting keeps "it never linked" a real answer the caller asserts on, instead of a timeout hiding which half of the journey failed.
    /// </remarks>
    private async Task<string?> WaitForLinkAsync<TDto>(string route, string id, string? previous = null)
        where TDto : IReferenceLinkedDto
    {
        for (var attempt = 0; attempt < 500; attempt++)
        {
            var referenceId = await ReadLinkAsync<TDto>(route, id);
            var settled = previous is null ? !string.IsNullOrEmpty(referenceId) : referenceId != previous;
            if (settled) return referenceId;

            await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
        }

        return previous is null ? null : await ReadLinkAsync<TDto>(route, id);
    }

    /// <summary>
    /// Reads the item's current reference link, remembering every reference it has ever pointed at so the run leaves the database as it found it.
    /// </summary>
    /// <remarks>
    /// Every reference these tests cause to be created has to go, and the currently-linked one is not enough: a case that moves an item from one reference to another would otherwise leave the first behind.
    /// A leftover is not untidy here, it is fatal to the point: these tests prove the provider was reached, which is only observable while nothing local answers.
    /// </remarks>
    private async Task<string?> ReadLinkAsync<TDto>(string route, string id)
        where TDto : IReferenceLinkedDto
    {
        var item = await Fixture.ApiHttpClient.GetFromJsonAsync<TDto>($"{route}/{id}", TestContext.Current.CancellationToken);
        if (!string.IsNullOrEmpty(item?.ReferenceId) && _seenReferenceIds.Add(item.ReferenceId))
        {
            var referenceId = item.ReferenceId;
            var collection = ReferenceCollections[route];
            TrackCleanup(() => Fixture.RemoveReferencesAsync(collection, [referenceId]));
        }

        return item?.ReferenceId;
    }

    private static readonly Dictionary<string, string> ReferenceCollections = new()
    {
        ["/api/tv-shows"] = "tvshow_reference",
        ["/api/movies"] = "movie_reference",
        ["/api/books"] = "book_reference",
        ["/api/albums"] = "album_reference"
    };

    private readonly HashSet<string> _seenReferenceIds = [];
}
