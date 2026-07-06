using System.Net;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public class ReferenceDataAdminResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    /// <summary>
    /// The standard test user has no "role" claim, so the "AdminOnly" policy must reject it - ASP.NET
    /// Core returns 403 (not 401) for an authenticated caller that fails a policy check.
    /// </summary>
    [Fact]
    public async Task GetUnresolved_WithoutAdminRole_IsForbidden()
    {
        await Authenticate();

        await GetAsync("/api/reference-data/unresolved?type=TvShow", HttpStatusCode.Forbidden);
    }
}
