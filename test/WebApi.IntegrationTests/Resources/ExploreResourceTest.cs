using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
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
/// Explore controller coverage: authentication, the domain guard (Book/Album aren't reference-ranked
/// discovery domains), the dismiss/undo round-trip for each domain's own provider id space, and the
/// suggestion listing itself.
/// <para>
/// The listing is testable here at all only because the read path now pages the locally stored
/// <c>explore_catalogue</c> instead of calling TMDB/RAWG per request - it used to need real provider keys and
/// was left to the Playwright smoke suite. That these tests pass against a host with the reference sync
/// disabled is itself the proof that no provider is reached.
/// </para>
/// </summary>
public class ExploreResourceTest(KestrelWebAppFactory<Program> factory) : ResourceTestBase(factory)
{
    [Fact]
    public async Task Explore_RequiresAuthentication()
    {
        await GetAsync("/api/explore/Movie", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Explore_RejectsADomainWhereDiscoveryDoesNotApply()
    {
        await Authenticate();
        // Book is not a reference-ranked Explore domain - the controller answers 400 (before any TMDB call).
        await GetAsync("/api/explore/Book", HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Dismiss_AndUndo_AreIdempotentAndReturnNoContent()
    {
        await Authenticate();

        // dismissing twice is idempotent (both 204); undo also 204 - none of this touches a provider
        await DismissAsync("Movie", "999999");
        await DismissAsync("Movie", "999999");
        await DeleteAsync("/api/explore/Movie/dismiss/999999");
    }

    [Fact]
    public async Task Dismiss_KeepsEachDomainsProviderIdSpaceSeparate()
    {
        await Authenticate();

        // the same bare number means a TMDB movie and a RAWG game - two different titles. The unique key
        // carries the provider, so both inserts succeed and undoing one leaves the other in place.
        await DismissAsync("Movie", "424242");
        await DismissAsync("VideoGame", "424242");
        await DeleteAsync("/api/explore/Movie/dismiss/424242");
        await DeleteAsync("/api/explore/VideoGame/dismiss/424242");
    }

    [Fact]
    public async Task Get_PagesThroughTheStoredRanking_WithoutCallingAProvider()
    {
        await Authenticate();
        var seeded = await SeedRankingAsync();

        var first = await GetAsync<ExploreSuggestionPageDto>($"/api/explore/Movie?count=2&after={SeedRankBase}");
        var second = await GetAsync<ExploreSuggestionPageDto>($"/api/explore/Movie?count=2&after={first.NextCursor}");

        // that this returns anything at all is the point: the host has no provider credentials in play here
        // and the reference sync is disabled, so every one of these titles came from the local catalogue.
        first.Items.Select(i => i.ExternalId).Should().Equal([seeded[0], seeded[1]]);
        first.NextCursor.Should().Be(SeedRankBase + 2);
        second.Items.Select(i => i.ExternalId).Should().Equal([seeded[2], seeded[3]]);
        first.Items[0].Rating.Should().Be(9.5);
        first.Items[0].RatingScale.Should().Be(10, "movies default to TMDB's 0-10 scale");
    }

    [Fact]
    public async Task Get_ExcludesADismissedTitle_AndKeepsPagingPastIt()
    {
        await Authenticate();
        var seeded = await SeedRankingAsync();
        await DismissAsync("Movie", seeded[1]);

        var page = await GetAsync<ExploreSuggestionPageDto>($"/api/explore/Movie?count=2&after={SeedRankBase}");

        // the dismissed entry is skipped and the page is filled from further down the ranking rather than
        // coming back short - the cursor still advances past everything examined.
        page.Items.Select(i => i.ExternalId).Should().Equal([seeded[0], seeded[2]]);
        page.NextCursor.Should().Be(SeedRankBase + 3);
    }

    /// <summary>
    /// Rank offset the seeded entries start above. Paging from it makes these tests independent of whatever
    /// else the shared <c>explore_catalogue</c> holds - the real ranking a developer may have populated by
    /// running the app sits far below, so a cursor at this offset skips it deterministically.
    /// </summary>
    private const int SeedRankBase = 900_000;

    /// <summary>
    /// Writes four synthetic entries into the movie ranking and registers them for deletion as they are
    /// created. Synthetic ids under a unique index accumulate and collide, so unlike a reference document
    /// earned from a real provider these must always be removed.
    /// </summary>
    private async Task<List<string>> SeedRankingAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IExploreCatalogueRepository>();
        var externalIds = Enumerable.Range(0, 4).Select(_ => TestExternalId.New()).ToList();

        var entries = externalIds.Select((externalId, index) => new ExploreCatalogueEntryModel
        {
            ItemType = ExploreItemType.Movie,
            Ranking = "tmdb",
            ExternalId = externalId,
            Rank = SeedRankBase + index + 1,
            Title = $"Explore Paging Test {externalId}",
            Year = 1999,
            Ratings = new Dictionary<string, double> { ["tmdb"] = 9.5 },
            RefreshedAt = DateTime.UtcNow
        }).ToList();

        foreach (var externalId in externalIds)
        {
            TrackDocumentsWhere("explore_catalogue", Builders<BsonDocument>.Filter.Eq("external_id", externalId));
        }

        await repository.UpsertManyAsync(entries);
        return externalIds;
    }

    /// <summary>
    /// Dismissing and registering the undo together. The undo is also what each test asserts on, but a
    /// dismissal recorded before an assertion fails would otherwise stay in <c>explore_dismissal</c> and
    /// silently hide that title from the owner's real Explore feed.
    /// </summary>
    private async Task DismissAsync(string itemType, string externalId)
    {
        await PostNoContentAsync($"/api/explore/{itemType}/dismiss/{externalId}", new { });
        TrackResource($"/api/explore/{itemType}/dismiss", externalId);
    }
}
