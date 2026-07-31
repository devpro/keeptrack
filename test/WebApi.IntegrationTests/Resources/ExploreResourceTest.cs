using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Explore controller coverage that doesn't depend on a live provider call: authentication, the domain guard
/// (Book/Album aren't reference-ranked discovery domains), and the dismiss/undo round-trip for each domain's
/// own provider id space. The suggestion listing itself hits the real TMDB/RAWG top-rated APIs, so it's
/// exercised by the Playwright smoke suite (already provisioned with those keys), not here.
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
