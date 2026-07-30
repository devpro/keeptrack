using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Explore controller coverage that doesn't depend on a live TMDB call: authentication, the domain guard
/// (Book/Album aren't reference-ranked discovery domains), and the dismiss/undo round-trip. The suggestion
/// listing itself hits the real TMDB top-rated API, so it's exercised by the Playwright smoke suite (which is
/// already provisioned with a TMDB key), not here.
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

        // dismissing twice is idempotent (both 204); undo also 204 - none of this touches TMDB
        await PostNoContentAsync("/api/explore/Movie/dismiss/999999", new { });
        await PostNoContentAsync("/api/explore/Movie/dismiss/999999", new { });
        await DeleteAsync("/api/explore/Movie/dismiss/999999");
    }
}
