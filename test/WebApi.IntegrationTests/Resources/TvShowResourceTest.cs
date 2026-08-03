using System.Net;
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
        var created = await CreateAsync($"/{ResourceEndpoint}", new TvShowDto
        {
            Title = title,
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical }],
            IsWishlisted = true
        });

        var owned = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
        owned.Items.Should().ContainSingle(s => s.Id == created.Id);

        // this is the WishlistController filter-probe, not a list-page UI filter (removed) - still real API behavior
        var wishlisted = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={title}");
        wishlisted.Items.Should().ContainSingle(s => s.Id == created.Id);
    }

    /// <summary>
    /// Episodes are a separate top-level collection referencing their show by id (see CLAUDE.md's "Child
    /// entities" section) - without TvShowController.OnDeletedAsync cascading the delete, a deleted show's
    /// whole watch history would be orphaned in MongoDB forever, only ever reachable via the now-gone show id.
    /// </summary>
    [Fact]
    public async Task TvShowResourceDelete_CascadesToItsEpisodes_IsOk()
    {
        await Authenticate();

        // both are registered even though the delete below is the point of the test: if the cascade is ever
        // broken, the orphaned episode is exactly what would otherwise be left behind.
        var show = await CreateAsync($"/{ResourceEndpoint}", new TvShowDto { Title = System.Guid.NewGuid().ToString() });
        var episode = await CreateAsync("/api/episodes", new EpisodeDto
        {
            TvShowId = show.Id!,
            SeasonNumber = 1,
            EpisodeNumber = 1
        });

        await DeleteAsync($"/{ResourceEndpoint}/{show.Id}");

        await GetAsync($"/api/episodes/{episode.Id}", HttpStatusCode.NotFound);
    }
}
