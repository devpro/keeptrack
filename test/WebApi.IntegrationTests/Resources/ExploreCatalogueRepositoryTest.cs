using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// <see cref="IExploreCatalogueRepository"/> against real MongoDB. Everything asserted here is storage
/// semantics a mocked repository cannot prove: that the rank cursor really pages, that an upsert merges
/// ratings key by key instead of replacing the map, that the prune deletes by "older than this pass", and
/// that one ordering's entries never collide with another's.
/// </summary>
public class ExploreCatalogueRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    private const string CollectionName = "explore_catalogue";

    /// <summary>
    /// A ranking name unique to each test. The collection is keyed by (item type, ranking, external id) and
    /// the suite shares one long-lived database, so scoping every test to its own synthetic ranking is what
    /// keeps parallel classes - and the real "tmdb"/"rawg" rankings a developer may have populated by running
    /// the app - out of each other's way.
    /// </summary>
    private static string TestRanking() => $"test-{Guid.NewGuid():N}";

    private IExploreCatalogueRepository CreateRepository(IServiceScope scope) =>
        scope.ServiceProvider.GetRequiredService<IExploreCatalogueRepository>();

    /// <summary>
    /// Registers the whole synthetic ranking for deletion at the moment it is first written - never as a
    /// trailing <c>finally</c>, which wouldn't cover a failure partway through the writes. These are
    /// made-up ids under a unique index, so leaving one behind fails a later run rather than merely
    /// cluttering the database.
    /// </summary>
    private void TrackRanking(string ranking) =>
        TrackDocumentsWhere(CollectionName, Builders<BsonDocument>.Filter.Eq("ranking", ranking));

    private static ExploreCatalogueEntryModel Entry(
        string ranking,
        string externalId,
        int rank,
        DateTime refreshedAt,
        Dictionary<string, double>? ratings = null,
        Dictionary<string, string>? webUrls = null) => new()
        {
            ItemType = ExploreItemType.Movie,
            Ranking = ranking,
            ExternalId = externalId,
            Rank = rank,
            Title = $"Explore Catalogue Test {externalId}",
            Year = 1999,
            Ratings = ratings ?? [],
            WebUrls = webUrls ?? [],
            RefreshedAt = refreshedAt
        };

    [Fact]
    public async Task FindRankedAsync_PagesInRankOrder_FromTheCursor()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var now = DateTime.UtcNow;

        // deliberately inserted out of order: the sort has to come from the query, not from insertion order
        // (an unsorted skip/limit read is exactly what duplicates and drops entries across pages).
        await repository.UpsertManyAsync([Entry(ranking, "c", 3, now), Entry(ranking, "a", 1, now), Entry(ranking, "b", 2, now)]);

        var first = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, 0, 2);
        var second = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, first[^1].Rank, 2);
        var third = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, second[^1].Rank, 2);

        first.Select(e => e.ExternalId).Should().Equal(["a", "b"]);
        second.Select(e => e.ExternalId).Should().Equal(["c"]);
        third.Should().BeEmpty("an empty page is how the read path knows the ranking is exhausted");
    }

    [Fact]
    public async Task UpsertManyAsync_IsKeyedByTheNaturalKey_SoARepeatedPassUpdatesRatherThanDuplicates()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);

        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow, new Dictionary<string, double> { ["tmdb"] = 8.0 })]);
        // next week's pass: the same title, now ranked lower and rated slightly differently
        await repository.UpsertManyAsync([Entry(ranking, "a", 5, DateTime.UtcNow, new Dictionary<string, double> { ["tmdb"] = 8.2 })]);

        var entries = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, 0, 10);
        entries.Should().ContainSingle("the natural key is unique, so the second pass updated the first pass's document");
        entries[0].Rank.Should().Be(5);
        entries[0].Ratings["tmdb"].Should().Be(8.2);
    }

    [Fact]
    public async Task UpsertManyAsync_MergesRatingsPerKey_KeepingOneTheRefreshDidNotFetch()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);

        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow, new Dictionary<string, double> { ["tmdb"] = 8.0 })]);
        await repository.RecordRatingAttemptAsync(ExploreItemType.Movie, ranking, "a", "imdb", 8.6);

        // an ordinary refresh only knows what the provider's listing carried, i.e. the TMDB score
        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow, new Dictionary<string, double> { ["tmdb"] = 8.1 })]);

        var entries = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, 0, 10);
        // replacing the whole ratings subdocument would silently discard the IMDb value, which costs two
        // provider calls and a slot of the bounded weekly backfill budget to obtain.
        entries[0].Ratings.Should().BeEquivalentTo(new Dictionary<string, double> { ["tmdb"] = 8.1, ["imdb"] = 8.6 });
    }

    [Fact]
    public async Task FindMissingRatingOrLinkAsync_ReturnsUnratedEntriesInRankOrder_AndSkipsRecentlyAttemptedOnes()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var now = DateTime.UtcNow;

        await repository.UpsertManyAsync(
        [
            // rated *and* linked: nothing left to learn about this source
            Entry(ranking, "done", 1, now, new Dictionary<string, double> { ["imdb"] = 9.0 },
                new Dictionary<string, string> { ["imdb"] = "https://www.imdb.com/title/tt0009/" }),
            Entry(ranking, "attempted", 2, now),
            Entry(ranking, "pending-low", 4, now),
            Entry(ranking, "pending-high", 3, now)
        ]);
        // a title the provider has no rating for: attempted, stamped, no value stored
        await repository.RecordRatingAttemptAsync(ExploreItemType.Movie, ranking, "attempted", "imdb", null);

        var pending = await repository.FindMissingRatingOrLinkAsync(ExploreItemType.Movie, ranking, "imdb", now.AddDays(-90), 10);

        // the finished one is done; the fruitless attempt is stamped and must not be retried this soon, or it
        // would hold a slot of the budget every pass and coverage would never reach the entries below it.
        // That the stamped-but-linkless "attempted" entry stays out is also what proves the link half can't
        // loop: a title with no provider id has no rating and no link, and only the windowed branch takes it.
        pending.Select(e => e.ExternalId).Should().Equal(["pending-high", "pending-low"]);
    }

    [Fact]
    public async Task FindMissingRatingOrLinkAsync_TakesARatedEntryThatIsStillMissingItsLink()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var now = DateTime.UtcNow;

        // exactly what a pass from before links were stored leaves behind: the rating was obtained (so the
        // provider id was resolved), the link wasn't.
        await repository.UpsertManyAsync([Entry(ranking, "a", 1, now, new Dictionary<string, double> { ["imdb"] = 9.0 })]);
        await repository.RecordRatingAttemptAsync(ExploreItemType.Movie, ranking, "a", "imdb", 9.0);

        var pending = await repository.FindMissingRatingOrLinkAsync(ExploreItemType.Movie, ranking, "imdb", now.AddDays(-90), 10);

        // deliberately not subject to the re-attempt window: it was attempted seconds ago, and waiting 90 days
        // for a link one lookup can produce today would leave the top of the ranking linking to the wrong site.
        pending.Should().ContainSingle().Which.ExternalId.Should().Be("a");
    }

    [Fact]
    public async Task SetWebUrlAsync_StoresTheLink_AndAnOrdinaryRefreshKeepsIt()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var discoveryLink = new Dictionary<string, string> { ["tmdb"] = "https://www.themoviedb.org/movie/9" };

        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow, webUrls: discoveryLink)]);
        await repository.SetWebUrlAsync(ExploreItemType.Movie, ranking, "a", "imdb", "https://www.imdb.com/title/tt0009/");
        // next week's pass knows only the link its own listing carried
        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow, webUrls: discoveryLink)]);

        var entries = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, 0, 10);

        // same rule as the ratings map: replacing it wholesale would discard the IMDb link every single week,
        // and the entry would then never be picked up again for it (it has a rating, so nothing looks pending).
        entries[0].WebUrls.Should().BeEquivalentTo(new Dictionary<string, string>
        {
            ["tmdb"] = "https://www.themoviedb.org/movie/9",
            ["imdb"] = "https://www.imdb.com/title/tt0009/"
        });
    }

    [Fact]
    public async Task FindMissingRatingOrLinkAsync_ReattemptsAnOldFruitlessAttempt()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);

        await repository.UpsertManyAsync([Entry(ranking, "a", 1, DateTime.UtcNow)]);
        await repository.RecordRatingAttemptAsync(ExploreItemType.Movie, ranking, "a", "imdb", null);

        // "not attempted since" in the future: everything already attempted is due again
        var pending = await repository.FindMissingRatingOrLinkAsync(ExploreItemType.Movie, ranking, "imdb", DateTime.UtcNow.AddDays(1), 10);

        pending.Should().ContainSingle().Which.ExternalId.Should().Be("a");
    }

    [Fact]
    public async Task DeleteStaleAsync_RemovesOnlyWhatTheCurrentPassDidNotRewrite()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var lastWeek = DateTime.UtcNow.AddDays(-7);

        await repository.UpsertManyAsync([Entry(ranking, "stays", 1, lastWeek), Entry(ranking, "drops-out", 2, lastWeek)]);

        var passStartedAt = DateTime.UtcNow;
        await repository.UpsertManyAsync([Entry(ranking, "stays", 1, passStartedAt)]);
        var deleted = await repository.DeleteStaleAsync(ExploreItemType.Movie, ranking, passStartedAt);

        deleted.Should().Be(1);
        var entries = await repository.FindRankedAsync(ExploreItemType.Movie, ranking, 0, 10);
        entries.Select(e => e.ExternalId).Should().Equal(["stays"]);
    }

    [Fact]
    public async Task FindOldestRefreshedAtAsync_ReportsTheOldestStamp_SoAPartialPassStillReadsAsStale()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var ranking = TestRanking();
        TrackRanking(ranking);
        var lastWeek = DateTime.UtcNow.AddDays(-7);

        // exactly the shape a pass that died halfway leaves behind: some entries rewritten just now, the rest
        // still carrying last week's stamp because the prune never ran.
        await repository.UpsertManyAsync([Entry(ranking, "old", 2, lastWeek), Entry(ranking, "new", 1, DateTime.UtcNow)]);

        var oldest = await repository.FindOldestRefreshedAtAsync(ExploreItemType.Movie, ranking);

        // taking the newest stamp instead would read this as "just refreshed" and skip the retry, leaving a
        // half-built ranking in place until something else happened to change.
        oldest.Should().BeCloseTo(lastWeek, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task FindOldestRefreshedAtAsync_ForARankingThatWasNeverBuilt_ReturnsNull()
    {
        using var scope = Factory.Services.CreateScope();

        var oldest = await CreateRepository(scope).FindOldestRefreshedAtAsync(ExploreItemType.Movie, TestRanking());

        oldest.Should().BeNull();
    }

    [Fact]
    public async Task FindExternalIdsAsync_ProjectsOnlyTheRequestedProvidersIds()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();

        // a TV reference is the worst case for the unprojected read this replaced: it embeds the whole
        // episode guide, so fetching the document to extract one id drags every episode along with it.
        var tmdbId = TestExternalId.New();
        var reference = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = "Explore Projection Test",
            TitleNormalized = "explore projection test",
            Year = 2001,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId },
            Episodes = [.. Enumerable.Range(1, 20).Select(n => new ReferenceEpisodeModel { SeasonNumber = 1, EpisodeNumber = n, Title = $"Episode {n}" })]
        });
        TrackDocument("tvshow_reference", reference.Id);

        var externalIds = await repository.FindExternalIdsAsync([reference.Id!], "tmdb");
        var unknownProvider = await repository.FindExternalIdsAsync([reference.Id!], "rawg");

        externalIds.Should().Equal([tmdbId]);
        // a reference resolved through another provider has no id in this number space and must contribute
        // nothing - never an empty string, which would match an entry whose own id failed to parse.
        unknownProvider.Should().BeEmpty();
    }

    [Fact]
    public async Task FindExternalIdsAsync_ForNoIds_MakesNoQuery()
    {
        using var scope = Factory.Services.CreateScope();

        var externalIds = await scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>().FindExternalIdsAsync([], "tmdb");

        // an owner who tracks nothing linked must not turn into an unfiltered $in over the whole collection
        externalIds.Should().BeEmpty();
    }

    [Fact]
    public async Task Rankings_AreIsolatedFromEachOther()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = CreateRepository(scope);
        var (first, second) = (TestRanking(), TestRanking());
        TrackRanking(first);
        TrackRanking(second);
        var now = DateTime.UtcNow;

        // the same provider id legitimately appears in both of a domain's orderings (a game ranked by RAWG's
        // score and by Metacritic's), at different positions - they must not collide on the unique key.
        await repository.UpsertManyAsync([Entry(first, "same-id", 1, now)]);
        await repository.UpsertManyAsync([Entry(second, "same-id", 9, now)]);

        (await repository.CountAsync(ExploreItemType.Movie, first)).Should().Be(1);
        (await repository.FindRankedAsync(ExploreItemType.Movie, second, 0, 10))[0].Rank.Should().Be(9);
    }
}
