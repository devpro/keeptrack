using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.Domain.Models;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the Explore page against a seeded <c>explore_catalogue</c>: the ranking renders, dismissing a
/// suggestion drops its card for good, "Load more" appends the next page, and the domain tabs each show their
/// own ranking. The API-level <c>ExploreResourceTest</c> already proves the cursor paging and the exclusion
/// rules; what only a browser can prove is that the page's own state machine (per-tab cache, busy guard,
/// top-up, <c>?tab=</c> navigation) is wired to it correctly.
/// <para>
/// Seeding the catalogue is what makes all of this deterministic and provider-free - the real ranking is
/// written weekly from TMDB/RAWG by a pass this host never runs. The one exception is
/// <see cref="Add_CreatesTheSuggestedMovie_LinkedToItsReference"/>: adding resolves the reference from the
/// exact provider id the suggestion carries, so that one entry has to carry a *real* TMDB id, exactly like
/// <see cref="MovieSmokeTest"/> links a real title.
/// </para>
/// <para>
/// Video games are deliberately not covered. The tab is member-only and its ranking comes from RAWG, which
/// has been unavailable since 2026-08-02; a suggestion listing can be seeded around that, but the add path
/// can't, and half a domain's coverage isn't worth a test that reads as complete. Movies and TV shows exercise
/// every code path the page has.
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

    /// <summary>Mirrors <c>ExplorePage.razor</c>'s own <c>PageCount</c> - how many suggestions one fetch asks for.</summary>
    private const int PageCount = 24;

    /// <summary>A real TMDB movie id, so the add path resolves a genuine reference document (see the class summary).</summary>
    private const string ShawshankTmdbId = "278";

    private const string ShawshankTitle = "The Shawshank Redemption";

    /// <summary>What a user would type to find it again in their own list.</summary>
    private const string ShawshankSearch = "Shawshank";

    /// <summary>
    /// Every copy of that exact title the tenant holds. The full title, not the short search term, so the
    /// removal above matches as narrowly as the list endpoint's "contains" search allows.
    /// </summary>
    private static string TrackedCopiesQuery => $"/api/movies?search={Uri.EscapeDataString(ShawshankTitle)}";

    /// <summary>
    /// Seeded suggestions all carry this year, asserted on a card to prove the meta line renders the entry's
    /// own data rather than a placeholder.
    /// </summary>
    private const int SeedYear = 2001;

    private const double SeedRating = 9.5;

    [Fact]
    public async Task Dismiss_RemovesTheSuggestionForGood()
    {
        SkipUnlessSeedable();

        var seeded = await SeedAsync(ExploreItemType.Movie, count: 3);
        var explore = await (await new HomePage(Page).OpenAsync()).OpenExploreAsync();

        // the card's meta line renders the entry's own year and rating - the page formats the rating with the
        // invariant culture, so the expectation has to as well (a French agent would look for "9,5").
        await Assertions.Expect(explore.Card(seeded[0].Title)).ToContainTextAsync(SeedYear.ToString(CultureInfo.InvariantCulture));
        await Assertions.Expect(explore.Card(seeded[0].Title)).ToContainTextAsync(SeedRating.ToString("0.0", CultureInfo.InvariantCulture));

        await DismissAsync(explore, seeded[1]);

        await Assertions.Expect(explore.Card(seeded[0].Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(seeded[2].Title)).ToBeVisibleAsync();

        // Refresh drops the page's cached tab and re-fetches: the dismissal only survives that if it was
        // recorded server-side, which is the half a "card disappeared" assertion on its own can't tell apart
        // from the client simply having removed it from a list.
        await explore.RefreshAsync(seeded[0].Title);
        await Assertions.Expect(explore.Card(seeded[1].Title)).ToBeHiddenAsync();
        await Assertions.Expect(explore.ErrorAlert).ToBeHiddenAsync();
    }

    [Fact]
    public async Task LoadMore_AppendsTheNextPageBelowTheCurrentCards()
    {
        SkipUnlessSeedable();

        // one more than a page, so the first fetch comes back full with the ranking not yet exhausted
        var seeded = await SeedAsync(ExploreItemType.Movie, count: PageCount + 2);
        var explore = await (await new HomePage(Page).OpenAsync()).OpenExploreAsync();

        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount);
        await Assertions.Expect(explore.Card(seeded[PageCount].Title)).ToBeHiddenAsync();

        await explore.LoadMoreAsync(seeded[PageCount].Title);

        // appended below what was already on screen, not reshuffled - the first card is still the first
        await Assertions.Expect(explore.Cards).ToHaveCountAsync(PageCount + 2);
        await Assertions.Expect(explore.Cards.First).ToContainTextAsync(seeded[0].Title);
        // the ranking is exhausted now, so the server returns a null cursor and the button goes
        await explore.ExpectNoLoadMoreAsync();
    }

    [Fact]
    public async Task Tabs_ShowEachDomainsOwnRanking()
    {
        SkipUnlessSeedable();

        var movie = (await SeedAsync(ExploreItemType.Movie, count: 1))[0];
        var show = (await SeedAsync(ExploreItemType.TvShow, count: 1))[0];

        var explore = await (await new HomePage(Page).OpenAsync()).OpenExploreAsync();
        await Assertions.Expect(explore.Card(movie.Title)).ToBeVisibleAsync();

        // selecting a tab is a real navigation, not local component state, so it lands in the query string
        await explore.SelectTabAsync("TV shows", TvShowsTabRegex());

        // each domain reads its own ranking - the movie suggestion isn't in the TV tab's list
        await Assertions.Expect(explore.Card(show.Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(movie.Title)).ToBeHiddenAsync();

        // and back, the way a user goes back: the other tab. Each tab keeps its own loaded list, so this is
        // also where a shared-state bug would show - as the TV suggestion still sitting under Movies.
        await explore.SelectTabAsync("Movies", MoviesTabRegex());
        await Assertions.Expect(explore.Card(movie.Title)).ToBeVisibleAsync();
        await Assertions.Expect(explore.Card(show.Title)).ToBeHiddenAsync();
    }

    [Fact]
    public async Task Add_CreatesTheSuggestedMovie_LinkedToItsReference()
    {
        SkipUnlessSeedable();

        await SeedAsync(Entry(ExploreItemType.Movie, rank: 1, ShawshankTitle, ShawshankTmdbId, year: 1994));

        // Registered before the click, because the add is where the item comes into existence and every step
        // after it is a place this test can stop early. TrackOpenItem takes over the moment the id is known.
        TrackItemsMatching("/api/movies", TrackedCopiesQuery);
        // ...and the same removal up front, which this scenario cannot do without: Explore's whole contract is
        // to hide what the caller already tracks, so "the tenant does not hold this title" is a precondition,
        // not an assertion. A database that already has it - a real one, or one where an earlier run of this
        // test died between the add and its cleanup - would otherwise show no card at all and fail here
        // forever. See SmokeTestBase.RemoveItemsMatchingAsync for why deleting what the test didn't create is
        // acceptable in this one place, and only here.
        await RemoveItemsMatchingAsync("/api/movies", TrackedCopiesQuery);

        var explore = await (await new HomePage(Page).OpenAsync()).OpenExploreAsync();

        await explore.AddAsync(ShawshankTitle);

        // the card only goes once the server has created *and* linked the item - the add awaits the resolve,
        // so this covers a real TMDB round trip and can be slower than an ordinary interaction.
        await Assertions.Expect(explore.Card(ShawshankTitle)).ToBeHiddenAsync(new LocatorAssertionsToBeHiddenOptions { Timeout = 30000 });
        await Assertions.Expect(explore.ErrorAlert).ToBeHiddenAsync();

        // ...and where a user goes to see what they just added.
        var movies = await explore.OpenMoviesAsync();
        await movies.SearchAsync(ShawshankSearch);
        await movies.OpenItemAsync(ShawshankTitle);

        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        // The item's own id, read off the detail-page URL - the same claim every media smoke test makes. The
        // reference document the link earns (and its cast's person_reference rows) is deliberately left in
        // place, like every other real-provider reference a smoke test resolves: a shared canonical fact
        // deduplicated by TMDB id, so a re-run reuses it and deleting it would only force a re-fetch.
        TrackOpenItem("/api/movies");

        // a cover is only rendered from a hydrated reference image, so it is the detail page's own evidence
        // that Explore's add resolved the reference by provider id rather than just creating a bare movie.
        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
    }

    /// <summary>
    /// Seeding writes straight to MongoDB, which only self-hosted mode can reach; every test here needs it.
    /// </summary>
    private void SkipUnlessSeedable()
    {
        SkipIfReadOnly();
        Assert.SkipUnless(Fixture.CanSeedDatabaseDirectly, "E2E_TARGET_URL is set; the Explore catalogue can't be seeded in a remote deployment.");
    }

    /// <summary>
    /// Writes <paramref name="count"/> consecutively-ranked suggestions into a domain's ranking and returns
    /// them in rank order. Titles are unique per call: the Explore listing also excludes anything whose
    /// normalized title the tenant already tracks, and every smoke test shares one tenant.
    /// </summary>
    private async Task<IReadOnlyList<ExploreCatalogueEntryModel>> SeedAsync(ExploreItemType type, int count)
    {
        var run = Guid.NewGuid().ToString("N")[..8];
        var entries = Enumerable.Range(1, count)
            .Select(rank => Entry(type, rank, $"E2e Explore {run} {rank:00}"))
            .ToList();

        await SeedAsync(entries.ToArray());
        return entries;
    }

    /// <summary>
    /// Dismisses a suggestion through the UI, registering the undo first.
    /// <para>
    /// A dismissal is a document of its own (<c>explore_dismissal</c>), owned by the run's identity and
    /// invisible in every list page - so nothing else would ever remove it, and a left-behind one silently
    /// hides that title from this account's real Explore feed forever. Registered before the click for the
    /// usual reason: every assertion after it is a place the test can stop early.
    /// </para>
    /// </summary>
    private async Task DismissAsync(ExplorePage explore, ExploreCatalogueEntryModel entry)
    {
        TrackCleanup(() => Fixture.DeleteItemAsync($"/api/explore/{entry.ItemType}/dismiss/{entry.ExternalId}"));
        await explore.DismissAsync(entry.Title);
    }

    /// <summary>
    /// Registers the removal <em>before</em> writing: a partially-written batch is exactly the case a cleanup
    /// registered afterwards would miss, and synthetic entries left behind under the collection's unique
    /// natural key are what fails tomorrow's run.
    /// </summary>
    private async Task SeedAsync(params ExploreCatalogueEntryModel[] entries)
    {
        var externalIds = entries.Select(entry => entry.ExternalId).ToList();
        TrackCleanup(() => Fixture.RemoveExploreCatalogueEntriesAsync(externalIds));
        await Fixture.SeedExploreCatalogueAsync(entries);
    }

    private static ExploreCatalogueEntryModel Entry(ExploreItemType type, int rank, string title, string? externalId = null, int? year = null) => new()
    {
        ItemType = type,
        // the ordering the page reads, taken from the app's own declaration rather than the literal "tmdb"
        Ranking = ExploreRankings.For(type, RatingSourceCatalog.Tmdb),
        ExternalId = externalId ?? $"e2e-{Guid.NewGuid():N}",
        Rank = rank,
        Title = title,
        Year = year ?? SeedYear,
        // both sources carry the same number, so the card shows a rating whichever one the admin setting
        // resolves to - the ranking is TMDB's either way (IMDb has no catalogue of its own).
        Ratings = new Dictionary<string, double> { [RatingSourceCatalog.Tmdb] = SeedRating, [RatingSourceCatalog.Imdb] = SeedRating },
        RefreshedAt = DateTime.UtcNow
    };
}
