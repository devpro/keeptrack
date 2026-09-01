using System;
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
/// Basic full-cycle CRUD coverage for <c>House</c>, same shape as <see cref="CarResourceTest"/>.
/// </summary>
public class HouseResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/houses";

    [Fact]
    public async Task HouseResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<HouseDto>()
            .Rules((f, o) =>
            {
                o.Name = f.Random.AlphaNumeric(14);
                o.City = f.Address.City();
                o.PropertyType = f.PickRandom<PropertyType>();
                o.MovedInAt = DateOnly.FromDateTime(f.Date.Past());
                o.MovedOutAt = DateOnly.FromDateTime(f.Date.Recent());
                o.ImageUrl = f.Internet.Url();
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Name = "New shiny name";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<HouseDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<HouseDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Name.Should().Be(updated.Name);
    }

    [Fact]
    public async Task HouseResourceSearch_FiltersByName_IsOk()
    {
        await Authenticate();

        var name = Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", new HouseDto { Name = name });

        var results = await GetAsync<PagedResult<HouseDto>>($"/{ResourceEndpoint}?search={name}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
    }

    [Fact]
    public async Task HouseResourceMetrics_ReturnsNotFound_ForAHouseThatDoesNotExist()
    {
        await Authenticate();

        await GetAsync($"/{ResourceEndpoint}/{MongoDB.Bson.ObjectId.GenerateNewId()}/metrics", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task HouseResourceMetrics_ReturnsEmptyMetrics_ForAHouseWithNoHistoryYet()
    {
        await Authenticate();

        var created = await CreateAsync($"/{ResourceEndpoint}", new HouseDto { Name = Guid.NewGuid().ToString() });

        var metrics = await GetAsync<HouseMetricsDto>($"/{ResourceEndpoint}/{created.Id}/metrics");
        metrics.CostHistory.Should().BeEmpty();
    }

    /// <summary>
    /// HouseHistory is a separate top-level collection referencing its house by id (see CLAUDE.md's "Child
    /// entities" section) - without HouseController.OnDeletedAsync cascading the delete, a deleted house's
    /// history would be orphaned in MongoDB forever, only ever reachable via the now-gone house id.
    /// </summary>
    [Fact]
    public async Task HouseResourceDelete_CascadesToItsHistory_IsOk()
    {
        await Authenticate();

        // both are registered even though the delete below is the point of the test: if the cascade is ever
        // broken, the orphaned history entry is exactly what would otherwise be left behind.
        var house = await CreateAsync($"/{ResourceEndpoint}", new HouseDto { Name = Guid.NewGuid().ToString() });
        var entry = await CreateAsync("/api/house-history", new HouseHistoryDto
        {
            HouseId = house.Id!,
            HistoryDate = DateOnly.FromDateTime(DateTime.Today),
            EventType = HouseEventType.Maintenance
        });

        await DeleteAsync($"/{ResourceEndpoint}/{house.Id}");

        await GetAsync($"/api/house-history/{entry.Id}", HttpStatusCode.NotFound);
    }
}
