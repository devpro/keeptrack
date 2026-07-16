using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public class TvShowResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/tv-shows";

    [Fact]
    public async Task TvShowResourceOwnedAndWishlistedFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new TvShowDto
        {
            Title = title,
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical }],
            IsWishlisted = true
        });

        try
        {
            var owned = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            owned.Items.Should().ContainSingle(s => s.Id == created.Id);

            var wishlisted = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={title}");
            wishlisted.Items.Should().ContainSingle(s => s.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
