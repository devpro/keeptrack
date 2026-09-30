using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Hosted through <see cref="RawgDefaultVideoGameWebAppFactory"/> so the video game default provider is RAWG
/// while DI registration order (IGDB first) stays untouched, proving the admin provider picker's default
/// follows <c>ReferenceData:VideoGameProvider</c> rather than <c>ReferenceClientRegistry.All</c>'s order.
/// </summary>
public class ReferenceDataAdminProviderDefaultResourceTest(RawgDefaultVideoGameWebAppFactory factory)
    : ResourceTestBase(factory), IClassFixture<RawgDefaultVideoGameWebAppFactory>
{
    [Fact]
    public async Task GetProviders_MarksTheConfiguredDefault_EvenWhenItIsNotFirstInRegistrationOrder()
    {
        await Authenticate();

        var providers = await GetAsync<List<ReferenceProviderDto>>("/api/reference-data/providers?type=VideoGame");

        providers.Select(p => p.Key).Should().Equal("igdb", "rawg");
        providers.Single(p => p.Key == "rawg").IsDefault.Should().BeTrue();
        providers.Single(p => p.Key == "igdb").IsDefault.Should().BeFalse();
    }
}
