using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The create-and-check journey for the four reference-linked domains that are not video games, against the
/// real providers: a tenant who records a real title and its creator or year ends up linked, and a tenant who
/// records something a provider has no answer for ends up linked to nothing at all.
/// <para>
/// These are deliberately not unit tests over the matching rule. Every regression reported here was in the
/// journey rather than the rule - what the provider was actually asked, and what was done with what it said -
/// and a test that feeds candidates in by hand can see neither. The same reason
/// <c>VideoGameReferenceMatchSmokeTest</c> exists for the fifth domain.
/// </para>
/// <para>
/// Each case is only meaningful while no local reference already answers it, and each one *creates* exactly
/// such a reference by passing, so every reference created here is deleted again - see
/// <see cref="ClearReferencesTitledAsync"/> and <c>TrackDocument</c>. This is the deliberate exception to
/// "reference documents from a real provider are left in place": here their absence is the premise.
/// </para>
/// </summary>
public class ReferenceMatchResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    /// <summary>
    /// Long enough to cover Open Library's measured 36-41s rating fallback inside a book resolve - see
    /// <see cref="PollForReferenceLinkAsync{TDto}"/>.
    /// </summary>
    private const int BookResolveSeconds = 90;

    /// <summary>
    /// TMDB's search is a fuzzy match over titles, not an exact one, so an ordinary show comes back beside
    /// everything else whose name contains one of its words: measured live, <c>The Bear</c> (2022) returns
    /// eight results and <c>Dark</c> (2017) returns fifteen, each with the show itself first and exactly named.
    /// A rule that only links when the provider returned exactly one row therefore refuses every one of them,
    /// which is what the owner reported as "creating a show with the right title and year does not match".
    /// </summary>
    [Theory]
    [InlineData("The Bear", 2022)]
    [InlineData("Dark", 2017)]
    public async Task CreatingATvShow_LinksItAutomatically_WhenTitleAndYearNameExactlyOneShow(string title, int year)
    {
        await Authenticate();
        await ClearLocalTvShowReferenceAsync(title, year);
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = title, Year = year });

        var linked = await PollForReferenceLinkAsync<TvShowDto>($"/api/tv-shows/{created.Id}");

        TrackDocument("tvshow_reference", linked);
        linked.Should().NotBeNullOrEmpty(
            "TMDB holds exactly one show named \"{0}\" ({1}), whatever else its fuzzy search returns alongside", title, year);
    }

    /// <summary>
    /// The other half of the same defect, and the dangerous one: a provider returning a single row is a fact
    /// about the <i>search</i>, never about the answer. Measured live, <c>search/tv?query=Fallout&amp;first_air_date_year=2025</c>
    /// returns exactly one result - <i>"Thirst Trap: The Fame. The Fantasy. The Fallout."</i> - because the
    /// year is a hard filter for TV and the 2024 show is excluded by it. Linking that is silent data loss:
    /// nothing in the app ever says a wrong reference was chosen.
    /// <para>
    /// Asserted through the button rather than through the create journey, because "nothing happened" has no
    /// observable moment to wait for. The button is synchronous and escalates to the provider, so it exercises
    /// the same resolution rule and answers deterministically.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RefreshReference_LeavesATvShowUnresolved_WhenTheProvidersOnlyAnswerIsNotThatShow()
    {
        await Authenticate();
        // the premise is that nothing local answers, and this case is unusually easy to poison: the pre-fix
        // rule *did* link this pair, so a run against a database that still holds that document finds the
        // wrong reference locally and never reaches the rule being tested
        await ClearLocalTvShowReferenceAsync("Fallout", 2025);
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = "Fallout", Year = 2025 });

        var refreshed = await PostThroughLiveProviderAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", "TMDB");

        refreshed!.ReferenceId.Should().BeNullOrEmpty(
            "TMDB's single answer for \"Fallout\" (2025) is \"Thirst Trap: The Fame. The Fantasy. The Fallout.\", which is not that show");
        refreshed.Title.Should().Be("Fallout", "a refusal must leave the tenant's own text exactly as it was");
    }

    /// <summary>
    /// Movies have the same defect for the same reason, and it is only less visible because a long title
    /// happens to narrow TMDB's fuzzy search to one row. Measured live: <c>Heat</c> (1995) returns fourteen
    /// results and <c>Alien</c> (1979) returns nine, the film itself first and exactly named in both.
    /// </summary>
    [Theory]
    [InlineData("Heat", 1995)]
    [InlineData("Alien", 1979)]
    public async Task CreatingAMovie_LinksItAutomatically_WhenTitleAndYearNameExactlyOneFilm(string title, int year)
    {
        await Authenticate();
        await ClearLocalMovieReferenceAsync(title, year);
        var created = await CreateAsync("/api/movies", new MovieDto { Title = title, Year = year });

        var linked = await PollForReferenceLinkAsync<MovieDto>($"/api/movies/{created.Id}");

        TrackDocument("movie_reference", linked);
        linked.Should().NotBeNullOrEmpty(
            "TMDB holds exactly one film named \"{0}\" ({1}), whatever else its fuzzy search returns alongside", title, year);
    }

    /// <summary>
    /// The year identifies a film here the way it identifies a game: TMDB holds a "Road House" from 1989 and
    /// another from 2024, both exactly named, and its <c>year</c> parameter is a soft boost rather than a
    /// filter - measured live, asking for 2024 returns the 1989 film too. So the year has to decide, and it
    /// has to decide client-side.
    /// </summary>
    [Fact]
    public async Task CreatingAMovie_LinksTheYearThatWasAskedFor_WhenTwoFilmsShareATitle()
    {
        await Authenticate();
        await ClearLocalMovieReferenceAsync("Road House", 1989);
        var created = await CreateAsync("/api/movies", new MovieDto { Title = "Road House", Year = 1989 });

        var linked = await PollForReferenceLinkAsync<MovieDto>($"/api/movies/{created.Id}");

        TrackDocument("movie_reference", linked);
        linked.Should().NotBeNullOrEmpty("TMDB holds exactly one \"Road House\" from 1989");
        var reference = await FindMovieReferenceAsync(linked!);
        reference!.Year.Should().Be(1989, "the 2024 remake is a different film with the same name");
    }

    /// <summary>
    /// A book's identity is its title and its author, never its year: measured live, Google Books answers
    /// <c>intitle:The Hobbit+inauthor:Tolkien</c> with 300 volumes, of which the first page alone holds
    /// editions from 1981, 1999, 2011 and 2012. Every one of them is the same book. A rule that waits for a
    /// single result can therefore never link a book at all, which is exactly what the owner reported.
    /// <para>
    /// The titles are ones no other class uses. This class <b>clears</b> a title before exercising it, since
    /// the absence of a local reference is its premise, and <c>BookProviderSearchAndLinkResourceTest</c> links
    /// "The Hobbit" through the real providers in parallel - sharing a title made the two delete each other's
    /// references, each passing alone and failing together.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("Dune", "Frank Herbert")]
    [InlineData("Foundation", "Isaac Asimov")]
    public async Task CreatingABook_LinksItAutomatically_WhenTitleAndAuthorNameOneWork(string title, string author)
    {
        await Authenticate();
        await ClearLocalBookReferenceAsync(title, author);
        var created = await CreateAsync("/api/books", new BookDto { Title = title, Author = author });

        var linked = await PollForReferenceLinkAsync<BookDto>($"/api/books/{created.Id}", BookResolveSeconds);

        TrackDocument("book_reference", linked);
        linked.Should().NotBeNullOrEmpty(
            "every volume Google Books returns for \"{0}\" by {1} is an edition of one work, not an ambiguity", title, author);
    }

    /// <summary>
    /// The author is what a book is identified by, so a wrong one must not be linked around. Google Books
    /// answers this title readily; nothing it returns is by this author.
    /// <para>
    /// The title is deliberately one no other test uses. <c>BookProviderSearchAndLinkResourceTest</c> links
    /// "The Hobbit" through the real providers and runs in parallel with this class, so sharing a title made
    /// this case find that reference locally and never reach the rule - green alone, red in a full run.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RefreshReference_LeavesABookUnresolved_WhenNothingTheProviderReturnsIsByThatAuthor()
    {
        await Authenticate();
        await ClearLocalBookReferenceAsync("Snow Crash", "Isaac Asimov");
        var created = await CreateAsync("/api/books", new BookDto { Title = "Snow Crash", Author = "Isaac Asimov" });

        var refreshed = await PostThroughLiveProviderAsync<BookDto?>($"/api/books/{created.Id}/refresh-reference", "Google Books");

        refreshed!.ReferenceId.Should().BeNullOrEmpty("Isaac Asimov did not write Snow Crash");
    }

    /// <summary>
    /// Albums have books' shape - a title, a creator, and many records of one release - plus Discogs' own
    /// year parameter, which is a <b>hard</b> filter: measured live, <c>q=Kid A&amp;artist=Radiohead&amp;year=2001</c>
    /// returns exactly one master, and it is <i>Amnesiac</i>. That is both failure modes in one query, and the
    /// same query without the year finds the album immediately.
    /// </summary>
    [Theory]
    [InlineData("Kid A", "Radiohead", 2000)]
    [InlineData("Thriller", "Michael Jackson", 1982)]
    public async Task CreatingAnAlbum_LinksItAutomatically_WhenTitleAndArtistNameOneRelease(string title, string artist, int year)
    {
        await Authenticate();
        await ClearLocalAlbumReferenceAsync(title, year, artist);
        var created = await CreateAsync("/api/albums", new AlbumDto { Title = title, Artist = artist, Year = year });

        var linked = await PollForReferenceLinkAsync<AlbumDto>($"/api/albums/{created.Id}");

        TrackDocument("album_reference", linked);
        linked.Should().NotBeNullOrEmpty(
            "Discogs holds one master named \"{0}\" by {1}; the rest of what it returns is not titled that at all", title, artist);
    }

    /// <summary>
    /// The album equivalent of the "Thirst Trap" case above, measured on the same query: a year Discogs
    /// filters hard on can leave one unrelated master as the only answer, and it must not be linked.
    /// </summary>
    [Fact]
    public async Task RefreshReference_LeavesAnAlbumUnresolved_WhenNothingTheProviderReturnsIsTitledThat()
    {
        await Authenticate();
        await ClearLocalAlbumReferenceAsync("Kid A", 2000, "Michael Jackson");
        var created = await CreateAsync("/api/albums", new AlbumDto { Title = "Kid A", Artist = "Michael Jackson", Year = 2000 });

        var refreshed = await PostThroughLiveProviderAsync<AlbumDto?>($"/api/albums/{created.Id}/refresh-reference", "Discogs");

        refreshed!.ReferenceId.Should().BeNullOrEmpty("Michael Jackson did not record Kid A");
    }

    /// <summary>
    /// The journey the detail page's button promises in all four domains: <i>"Not right? Edit the title or
    /// year below, then check again."</i> An item created before its year or author was known writes no
    /// reference at all, so a local-only re-check has nothing to find however correct the fields later become,
    /// and the button silently does nothing forever. Only video games escalated to the provider; these four
    /// did not.
    /// <para>
    /// Created bare and completed afterwards, which is the journey that reaches this button and the one that
    /// leaves nothing local behind.
    /// </para>
    /// </summary>
    [Fact]
    public async Task RefreshReference_LinksATvShowThroughTheProvider_WhenNoReferenceExistsYet()
    {
        await Authenticate();
        await ClearLocalTvShowReferenceAsync("Chernobyl", 2019);
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = "Chernobyl" });
        created.Year = 2019;
        await PutAsync($"/api/tv-shows/{created.Id}", created);

        var refreshed = await PostThroughLiveProviderAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", "TMDB");

        TrackDocument("tvshow_reference", refreshed!.ReferenceId);
        refreshed.ReferenceId.Should().NotBeNullOrEmpty("TMDB holds exactly one show named \"Chernobyl\" (2019)");
    }

    /// <summary>Movie equivalent of <see cref="RefreshReference_LinksATvShowThroughTheProvider_WhenNoReferenceExistsYet"/>.</summary>
    [Fact]
    public async Task RefreshReference_LinksAMovieThroughTheProvider_WhenNoReferenceExistsYet()
    {
        await Authenticate();
        await ClearLocalMovieReferenceAsync("Blade Runner", 1982);
        var created = await CreateAsync("/api/movies", new MovieDto { Title = "Blade Runner" });
        created.Year = 1982;
        await PutAsync($"/api/movies/{created.Id}", created);

        var refreshed = await PostThroughLiveProviderAsync<MovieDto?>($"/api/movies/{created.Id}/refresh-reference", "TMDB");

        TrackDocument("movie_reference", refreshed!.ReferenceId);
        refreshed.ReferenceId.Should().NotBeNullOrEmpty("TMDB holds exactly one film named \"Blade Runner\" (1982)");
    }

    /// <summary>
    /// Book equivalent, and the one where the missing field is the author rather than the year - which is what
    /// a book is identified by.
    /// </summary>
    [Fact]
    public async Task RefreshReference_LinksABookThroughTheProvider_WhenNoReferenceExistsYet()
    {
        await Authenticate();
        await ClearLocalBookReferenceAsync("Neuromancer", "William Gibson");
        var created = await CreateAsync("/api/books", new BookDto { Title = "Neuromancer" });
        created.Author = "William Gibson";
        await PutAsync($"/api/books/{created.Id}", created);

        var refreshed = await PostThroughLiveProviderAsync<BookDto?>($"/api/books/{created.Id}/refresh-reference", "Google Books");

        TrackDocument("book_reference", refreshed!.ReferenceId);
        refreshed.ReferenceId.Should().NotBeNullOrEmpty("Google Books holds Neuromancer by William Gibson");
    }

    /// <summary>Album equivalent, with the artist supplied after the fact.</summary>
    [Fact]
    public async Task RefreshReference_LinksAnAlbumThroughTheProvider_WhenNoReferenceExistsYet()
    {
        await Authenticate();
        await ClearLocalAlbumReferenceAsync("OK Computer", 1997, "Radiohead");
        var created = await CreateAsync("/api/albums", new AlbumDto { Title = "OK Computer", Year = 1997 });
        created.Artist = "Radiohead";
        await PutAsync($"/api/albums/{created.Id}", created);

        var refreshed = await PostThroughLiveProviderAsync<AlbumDto?>($"/api/albums/{created.Id}/refresh-reference", "Discogs");

        TrackDocument("album_reference", refreshed!.ReferenceId);
        refreshed.ReferenceId.Should().NotBeNullOrEmpty("Discogs holds one master \"OK Computer\" by Radiohead (1997)");
    }

    /// <summary>
    /// Polls a just-created item until its background reference resolution lands, or gives up. The resolve
    /// makes a provider call or two, so the budget is generous; returning empty is a real answer here (the
    /// caller asserts on it) rather than a timeout to throw on.
    /// <para>
    /// Books get much longer, and for a measured reason rather than as a hedge: resolving one runs
    /// <c>AddOpenLibraryRatingFallbackAsync</c>, and Open Library's <c>search.json</c> is the slowest endpoint
    /// any provider here calls - 36 to 41 seconds, already documented in <c>AGENTS.md</c>. A 30-second budget
    /// therefore expired while the resolution was still in flight and reported a failure for a link that did
    /// land, which is a flaky test rather than a real one.
    /// </para>
    /// </summary>
    private async Task<string?> PollForReferenceLinkAsync<TDto>(string url, int seconds = 30)
        where TDto : IReferenceLinkedDto
    {
        for (var attempt = 0; attempt < seconds; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
            var item = await GetAsync<TDto>(url);
            if (!string.IsNullOrEmpty(item.ReferenceId)) return item.ReferenceId;
        }

        return null;
    }

    /// <summary>
    /// Clears any reference document for this title before the case runs, because <b>its absence is the
    /// premise</b>: every case here proves the provider was reached, which is only observable while nothing
    /// local answers. A leftover turns the test green through the cheap local path while proving nothing at
    /// all - the same failure mode that made the first version of the video game scenarios pass with the fix
    /// disabled.
    /// <para>
    /// Deleting data the test did not create is normally forbidden here. This is the sanctioned exception, the
    /// same one <c>ExploreSmokeTest</c> takes for the same reason: the precondition is "nothing is tracked
    /// yet", so a database that already holds the document can never satisfy it however well the test cleans
    /// up afterwards. It is only safe because <c>TestDatabaseGuard</c> refuses any database whose name looks
    /// like a real one, and because these are shared provider facts that cost one call to re-earn.
    /// </para>
    /// <para>
    /// Matched on title alone, deliberately wider than the lookup being tested: what has to be absent is
    /// anything the local path could answer with, and that includes a document reached through an alias whose
    /// year or creator differs from the one this case supplies.
    /// </para>
    /// </summary>
    private async Task ClearReferencesTitledAsync(string collection, string title)
    {
        using var scope = Factory.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<IMongoDatabase>();
        var escaped = Regex.Escape(TitleNormalizer.Normalize(title));
        await database.GetCollection<BsonDocument>(collection).DeleteManyAsync(
            Builders<BsonDocument>.Filter.Or(
                Builders<BsonDocument>.Filter.Regex("title_normalized", new BsonRegularExpression($"^{escaped}$", "i")),
                Builders<BsonDocument>.Filter.Regex("matched_aliases.title", new BsonRegularExpression($"^{escaped}$", "i"))),
            CancellationToken.None);
    }

    private Task ClearLocalTvShowReferenceAsync(string title, int? year) => ClearReferencesTitledAsync("tvshow_reference", title);

    private Task ClearLocalMovieReferenceAsync(string title, int? year) => ClearReferencesTitledAsync("movie_reference", title);

    private Task ClearLocalBookReferenceAsync(string title, string author) => ClearReferencesTitledAsync("book_reference", title);

    private Task ClearLocalAlbumReferenceAsync(string title, int? year, string artist) => ClearReferencesTitledAsync("album_reference", title);

    private async Task<MovieReferenceModel?> FindMovieReferenceAsync(string referenceId)
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        return await repository.FindByIdAsync(referenceId);
    }
}
