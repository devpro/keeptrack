using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Basic full-cycle CRUD coverage for <c>TvShow</c>, closing the "no dedicated full CRUD test of its own" half of the finding tracked in docs/findings/by-design-and-gaps.md ("Thin test coverage"), same shape as <see cref="AlbumResourceTest"/>.
/// The filter and cascade tests below predate this and are left as they were.
/// </summary>
public class TvShowResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/tv-shows";

    [Fact]
    public async Task TvShowResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<TvShowDto>()
            .Rules((f, o) =>
            {
                o.Title = f.Random.AlphaNumeric(14);
                o.Year = f.Random.Int(1990, 2024);
                o.Notes = f.Lorem.Sentence();
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Title = "New shiny title";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<TvShowDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Title.Should().Be(updated.Title);

        await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        await GetAsync($"/{ResourceEndpoint}/{created.Id}", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task TvShowResourceSearch_FiltersByTitle_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", new TvShowDto { Title = title });

        var results = await GetAsync<PagedResult<TvShowDto>>($"/{ResourceEndpoint}?search={title}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
    }

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
