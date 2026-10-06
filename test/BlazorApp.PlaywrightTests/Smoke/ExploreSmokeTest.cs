using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the Explore page against a seeded <c>explore_catalogue</c>: the ranking renders, dismissing a suggestion drops its card for good,
/// a short list tops itself back up (from the button and on its own), and the domain tabs each show their own ranking.
/// The API-level <c>ExploreResourceTest</c> proves the cursor paging and the exclusion rules.
/// Only a browser proves the page's state machine (per-tab cache, busy guard, top-up, <c>?tab=</c> navigation) is wired to it.
/// <para>
/// Seeding the catalogue makes this deterministic and provider-free, since a pass this host never runs writes the real ranking weekly from TMDB and IGDB.
/// The two add tests are the exception: adding resolves the reference from the suggestion's exact provider id,
/// so those entries carry a real one, as <see cref="MovieSmokeTest"/> and <see cref="VideoGameSmokeTest"/> link real titles.
/// </para>
/// <para>
/// The list behaviours run over two domains, since more than the page differs between them.
/// Video games are member-only (their tab is behind an <c>AuthorizeView</c>), their ranking is IGDB's rather than TMDB's, and their dismissals use IGDB's id space.
/// TV shows share all of that with movies, so the tab test alone covers them.
/// </para>
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public partial class ExploreSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [GeneratedRegex("[?&]tab=TvShows")]
    private static partial Regex TvShowsTabRegex();

    [GeneratedRegex("[?&]tab=Movies")]
    private static partial Regex MoviesTabRegex();

    [GeneratedRegex("[?&]tab=VideoGames")]
    private static partial Regex VideoGamesTabRegex();

    /// <summary>Mirrors <c>ExplorePage.razor</c>'s <c>PageCount</c>: how many suggestions one fetch asks for, and the low-water mark a list is topped up at.</summary>
    private const int PageCount = 24;

    /// <summary>
    /// Seeded suggestions all carry this year, asserted on a card to prove the meta line renders the entry's own data rather than a placeholder.
    /// </summary>
    private const int SeedYear = 2001;

    /// <summary>
    /// What differs between two Explore domains, as far as this page is concerned: which tab shows it, and which rating sources a card of that domain can display.
    /// <para>
    /// Every displayable source carries the same seeded value, so a card shows a rating whichever one the admin setting resolves to.
    /// A domain's sources share a scale (TMDB and IMDb out of 10, IGDB's two out of 100), so the number on screen is the same either way.
    /// The video game entry names IGDB's sources, since this suite runs against IGDB (<c>End2EndFixture</c> requires its credentials),
    /// and a RAWG deployment would rank under other keys.
    /// </para>
    /// </summary>
    private sealed record Domain(ExploreItemType Type, string TabName, Regex TabUrl, IReadOnlyList<string> RatingSources, double Rating);

    private static readonly Domain s_movies =
        new(ExploreItemType.Movie, "Movies", MoviesTabRegex(), [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb], 9.5);

    private static readonly Domain s_tvShows =
        new(ExploreItemType.TvShow, "TV shows", TvShowsTabRegex(), [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb], 9.5);

    private static readonly Domain s_videoGames =
        new(ExploreItemType.VideoGame, "Video games", VideoGamesTabRegex(), [RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic], 95);

    private static Domain DomainFor(ExploreItemType type) => type switch
    {
        ExploreItemType.TvShow => s_tvShows,
        ExploreItemType.VideoGame => s_videoGames,
        _ => s_movies
    };

    /// <summary>One seeded suggestion as the test refers to it,
    /// written as one catalogue document per ranking (see <see cref="SeedAsync(Domain, IReadOnlyList{Suggestion})"/>).</summary>
    private sealed record Suggestion(ExploreItemType Type, string ExternalId, string Title, int Rank, int Year);

    [Theory]
    [InlineData(ExploreItemType.Movie)]
    [InlineData(ExploreItemType.VideoGame)]
    public async Task Dismiss_RemovesTheSuggestionForGood(ExploreItemType type)
    {
        await SkipUnlessSeedableAsync();
        var domain = DomainFor(type);

        var seeded = await SeedAsync(domain, count: 3);
        var explore = await OpenExploreAsync(domain);

        // The card's meta line renders the entry's year and rating, formatted with the invariant culture, so the expectation is too, or a French agent would look for "9,5".
        await Assertions.Expect(explore.Card(seeded[0].Title)).ToContainTextAsync(SeedYear.ToString(CultureInfo.InvariantCulture));
        await Assertions.Expect(explore.Card(seeded[0].Title)).ToContainTextAsync(domain.Rating.ToString("0.0", CultureInfo.InvariantCulture));

        await DismissAsync(explore, seeded[1]);

        await Assertions.Expect(explore.Card(seeded[0].Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(seeded[2].Title)).ToBeVisibleAsync();

        // Refresh drops the page's cached tab and re-fetches: the dismissal only survives that if it was recorded server-side,
        // which is the half a "card disappeared" assertion on its own can't tell apart from the client simply having removed it from a list.
        await explore.RefreshAsync(seeded[0].Title);
        await Assertions.Expect(explore.Card(seeded[1].Title)).ToBeHiddenAsync();
        await Assertions.Expect(explore.ErrorAlert).ToBeHiddenAsync();
    }

    [Theory]
    [InlineData(ExploreItemType.Movie)]
    [InlineData(ExploreItemType.VideoGame)]
    public async Task LoadMore_AppendsTheNextPageBelowTheCurrentCards(ExploreItemType type)
    {
        await SkipUnlessSeedableAsync();
        var domain = DomainFor(type);

        // one more than a page, so the first fetch comes back full with the ranking not yet exhausted
        var seeded = await SeedAsync(domain, count: PageCount + 2);
        var explore = await OpenExploreAsync(domain);

        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount);
        await Assertions.Expect(explore.Card(seeded[PageCount].Title)).ToBeHiddenAsync();

        await explore.LoadMoreAsync(seeded[PageCount].Title);

        // appended below what was on screen, not reshuffled, so the first card is still first
        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount + 2);
        await Assertions.Expect(explore.Cards.First).ToContainTextAsync(seeded[0].Title);
        // the ranking is exhausted now, so the server returns a null cursor and the button goes
        await explore.ExpectNoLoadMoreAsync();
    }

    /// <summary>
    /// The other half of "load more": nobody clicks anything.
    /// Removing a card takes the list below a full page,
    /// and the page continues from its cursor on its own so the user is never left with a thinning list they have to ask to refill.
    /// </summary>
    [Theory]
    [InlineData(ExploreItemType.Movie)]
    [InlineData(ExploreItemType.VideoGame)]
    public async Task RemovingACard_TopsTheListBackUpWithoutBeingAsked(ExploreItemType type)
    {
        await SkipUnlessSeedableAsync();
        var domain = DomainFor(type);

        // exactly one more than a page: the list drops below the low-water mark the moment a card goes, and there is exactly one suggestion behind the cursor to backfill it with.
        var seeded = await SeedAsync(domain, count: PageCount + 1);
        var explore = await OpenExploreAsync(domain);

        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount);
        await Assertions.Expect(explore.Card(seeded[PageCount].Title)).ToBeHiddenAsync();

        await DismissAsync(explore, seeded[0]);

        // back to a full page, with the next-ranked title appended at the end rather than the list being re-fetched from the top:
        // a top-up that re-requested page one would put seeded[1] first and could only ever backfill from titles already shown.
        await Assertions.Expect(explore.Card(seeded[PageCount].Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount);
        await Assertions.Expect(explore.Cards.Last).ToContainTextAsync(seeded[PageCount].Title);
        await Assertions.Expect(explore.ErrorAlert).ToBeHiddenAsync();
    }

    [Fact]
    public async Task Tabs_ShowEachDomainsOwnRanking()
    {
        await SkipUnlessSeedableAsync();

        var movie = (await SeedAsync(s_movies, count: 1))[0];
        var show = (await SeedAsync(s_tvShows, count: 1))[0];
        var game = (await SeedAsync(s_videoGames, count: 1))[0];

        var explore = await OpenExploreAsync(s_movies);
        await Assertions.Expect(explore.Card(movie.Title)).ToBeVisibleAsync();

        // selecting a tab is a real navigation, not local component state, so it lands in the query string
        await explore.SelectTabAsync(s_tvShows.TabName, s_tvShows.TabUrl);

        // each domain reads its own ranking, so the movie suggestion isn't in the TV tab's list
        await Assertions.Expect(explore.Card(show.Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(movie.Title)).ToBeHiddenAsync();

        // The video games tab is member-only, inside an AuthorizeView, so an account without the claim has no tab here and this click resolves nothing.
        await explore.SelectTabAsync(s_videoGames.TabName, s_videoGames.TabUrl);
        await Assertions.Expect(explore.Card(game.Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(show.Title)).ToBeHiddenAsync();

        // and back, the way a user goes back: the other tab.
        // Each tab keeps its own loaded list, so a shared-state bug would show here, as another domain's suggestion under Movies.
        await explore.SelectTabAsync(s_movies.TabName, s_movies.TabUrl);
        await Assertions.Expect(explore.Card(movie.Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(game.Title)).ToBeHiddenAsync();
    }

    /// <summary>
    /// What an add has to resolve against a real provider, per domain:
    /// a title with an unambiguous entry in that provider's catalogue, its id there, and where the item lands once it exists.
    /// </summary>
    private sealed record AddCase(
        Domain Domain,
        string Title,
        string ExternalId,
        int Year,
        string ApiRoute,
        string Search,
        Func<PageBase, Task<ListPage>> OpenList,
        Func<IPage, DetailPageBase> Detail);

    /// <summary>A real TMDB movie id, so the add path resolves a genuine reference document.</summary>
    private static readonly AddCase s_shawshank = new(
        s_movies, "The Shawshank Redemption", "278", 1994, "/api/movies", "Shawshank",
        page => page.OpenMoviesAsync(), page => new MovieDetailPage(page));

    /// <summary>
    /// The same for video games, against IGDB, the domain's default provider and the one this suite requires credentials for.
    /// IGDB 72 is Portal 2, the only entry that exact name matches on the live API, a safe fixture in a domain whose search returns editions and mods above a well-known game.
    /// No other smoke test tracks it, since <see cref="VideoGameSmokeTest"/> runs in parallel in the same tenant, and Explore hides what that tenant holds.
    /// </summary>
    private static readonly AddCase s_portal2 = new(
        s_videoGames, "Portal 2", "72", 2011, "/api/video-games", "Portal",
        page => page.OpenVideoGamesAsync(), page => new VideoGameDetailPage(page));

    [Fact]
    public Task Add_CreatesTheSuggestedMovie_LinkedToItsReference() => AddResolvesTheSuggestionAsync(s_shawshank);

    [Fact]
    public Task Add_CreatesTheSuggestedVideoGame_LinkedToItsReference() => AddResolvesTheSuggestionAsync(s_portal2);

    /// <summary>
    /// One add, end to end: the card's provider id has to become a created item linked to a reference document,
    /// which is the whole reason this path exists instead of the ordinary create (whose title search only links on a single candidate).
    /// </summary>
    private async Task AddResolvesTheSuggestionAsync(AddCase test)
    {
        await SkipUnlessSeedableAsync();

        await SeedAsync(test.Domain, [new Suggestion(test.Domain.Type, test.ExternalId, test.Title, Rank: 1, test.Year)]);

        // Every copy of that exact title the tenant holds.
        // The full title, not the short search term, so this matches as narrowly as the list endpoint's "contains" search allows.
        var trackedCopies = $"{test.ApiRoute}?search={Uri.EscapeDataString(test.Title)}";

        // Registered before the click, because the add is where the item comes into existence and every step after it is a place this test can stop early.
        // TrackOpenItem takes over the moment the id is known.
        TrackItemsMatching(test.ApiRoute, trackedCopies);
        // ...and the same removal up front: Explore hides what the caller tracks, so "the tenant does not hold this title" is a precondition, not an assertion.
        // A database that already has it (a real one, or one where an earlier run died between the add and its cleanup) would show no card and fail here forever.
        // See SmokeTestBase.RemoveItemsMatchingAsync for why deleting what the test didn't create is acceptable here, and only here.
        await RemoveItemsMatchingAsync(test.ApiRoute, trackedCopies);

        var explore = await OpenExploreAsync(test.Domain);

        await explore.AddAsync(test.Title);

        // The card goes only once the server has created and linked the item, since the add awaits the resolve, so this covers a real provider round trip and can be slow.
        await Assertions.Expect(explore.Card(test.Title)).ToBeHiddenAsync(new LocatorAssertionsToBeHiddenOptions { Timeout = 30000 });
        await Assertions.Expect(explore.ErrorAlert).ToBeHiddenAsync();

        // ...and where a user goes to see what they just added.
        var list = await test.OpenList(explore);
        await list.SearchAsync(test.Search);
        await list.OpenItemAsync(test.Title);

        var detail = test.Detail(Page);
        await detail.WaitForReadyAsync();
        // The item's own id, read off the detail-page URL, as every media smoke test does.
        // The reference document and its cast's person_reference rows stay, like every real-provider reference a smoke test resolves.
        // A shared canonical fact deduplicated by provider id is reused by a re-run, and deleting it would only force a re-fetch.
        TrackOpenItem(test.ApiRoute);

        // a cover is only rendered from a hydrated reference image,
        // so it is the detail page's own evidence that Explore's add resolved the reference by provider id rather than just creating a bare item.
        await Assertions.Expect(detail.CoverImage.First).ToBeVisibleAsync();
    }

    /// <summary>
    /// Opens Explore on <paramref name="domain"/>'s tab, the way a user reaches it.
    /// Movies need no click: the page lands there with no <c>?tab=</c>, and asserting that is the tab test's job, not every test's.
    /// </summary>
    private async Task<ExplorePage> OpenExploreAsync(Domain domain)
    {
        var explore = await (await new HomePage(Page).OpenAsync()).OpenExploreAsync();
        if (domain.Type != ExploreItemType.Movie)
        {
            await explore.SelectTabAsync(domain.TabName, domain.TabUrl);
        }

        return explore;
    }

    /// <summary>
    /// Seeding writes straight to MongoDB, which only self-hosted mode can reach; every test here needs it.
    /// <para>
    /// It also checks the premise of the whole class, that a seeded ranking is the whole ranking, and says so when it doesn't hold.
    /// Sharing a database with a suite whose <c>sync-now</c> tests rebuild the real TMDB ranking breaks it,
    /// with real films (The Godfather, Parasite) interleaved with the seeded ones by rank.
    /// The only symptom would be a card count that matches nothing, so naming the cause costs one count and saves the hunt.
    /// </para>
    /// </summary>
    private async Task SkipUnlessSeedableAsync()
    {
        SkipIfReadOnly();
        Assert.SkipUnless(Fixture.CanSeedDatabaseDirectly, "E2E_TARGET_URL is set; the Explore catalogue can't be seeded in a remote deployment.");

        var existing = await Fixture.CountExploreCatalogueEntriesAsync();
        Assert.True(existing == 0,
            $"explore_catalogue already holds {existing} entries this test didn't seed, so the Explore page will mix them into every "
            + "assertion here. They come from a real ranking rebuild - a sync-now run against this database. This suite defaults to its "
            + $"own database for that reason, so something pointed it elsewhere: check E2E_MONGODB_DATABASE (currently "
            + $"'{End2EndConfiguration.DatabaseName}').");
    }

    /// <summary>
    /// Writes <paramref name="count"/> consecutively-ranked suggestions into a domain's ranking and returns them in rank order.
    /// Titles are unique per call: the Explore listing also excludes anything whose normalized title the tenant already tracks, and every smoke test shares one tenant.
    /// </summary>
    private async Task<IReadOnlyList<Suggestion>> SeedAsync(Domain domain, int count)
    {
        var run = Guid.NewGuid().ToString("N")[..8];
        var suggestions = Enumerable.Range(1, count)
            .Select(rank => new Suggestion(domain.Type, $"e2e-{Guid.NewGuid():N}", $"E2e Explore {run} {rank:00}", rank, SeedYear))
            .ToList();

        await SeedAsync(domain, suggestions);
        return suggestions;
    }

    /// <summary>
    /// Writes one catalogue document per suggestion <em>per ordering the domain maintains</em>,
    /// since which of them the page reads follows an admin setting no test controls (see <see cref="End2EndFixture.ExploreRankingsFor"/>).
    /// Movies and TV have a single ordering and so a single document each; video games have one per IGDB rating source.
    /// <para>
    /// The removal is registered <em>before</em> writing: a partially-written batch is exactly the case a cleanup registered afterwards would miss,
    /// and synthetic entries left behind under the collection's unique natural key are what fails tomorrow's run.
    /// </para>
    /// </summary>
    private async Task SeedAsync(Domain domain, IReadOnlyList<Suggestion> suggestions)
    {
        var externalIds = suggestions.Select(suggestion => suggestion.ExternalId).ToList();
        TrackCleanup(() => Fixture.RemoveExploreCatalogueEntriesAsync(externalIds));

        var entries = Fixture.ExploreRankingsFor(domain.Type)
            .SelectMany(ranking => suggestions.Select(suggestion => Entry(domain, ranking, suggestion)))
            .ToList();
        await Fixture.SeedExploreCatalogueAsync(entries);
    }

    /// <summary>
    /// Dismisses a suggestion through the UI, registering the undo first.
    /// <para>
    /// A dismissal is a document of its own (<c>explore_dismissal</c>), owned by the run's identity and in no list page, so nothing else removes it.
    /// A leftover one would silently hide that title from this account's real Explore feed.
    /// Registered before the click for the usual reason: every assertion after it is a place the test can stop early.
    /// </para>
    /// </summary>
    private async Task DismissAsync(ExplorePage explore, Suggestion suggestion)
    {
        TrackCleanup(() => Fixture.DeleteItemAsync($"/api/explore/{suggestion.Type}/dismiss/{suggestion.ExternalId}"));
        await explore.DismissAsync(suggestion.Title);
    }

    private static ExploreCatalogueEntryModel Entry(Domain domain, string ranking, Suggestion suggestion) => new()
    {
        ItemType = suggestion.Type,
        Ranking = ranking,
        ExternalId = suggestion.ExternalId,
        Rank = suggestion.Rank,
        Title = suggestion.Title,
        Year = suggestion.Year,
        Ratings = domain.RatingSources.ToDictionary(source => source, _ => domain.Rating),
        RefreshedAt = DateTime.UtcNow
    };
}
