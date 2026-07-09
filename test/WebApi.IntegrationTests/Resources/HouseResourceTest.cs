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

        var initialItems = await GetAsync<PagedResult<HouseDto>>($"/{ResourceEndpoint}");

        var input = new Faker<HouseDto>()
            .Rules((f, o) =>
            {
                o.Name = f.Random.AlphaNumeric(14);
                o.Address = f.Address.StreetAddress();
                o.City = f.Address.City();
                o.PostalCode = f.Address.ZipCode();
                o.Country = f.Address.Country();
            })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Name = "New shiny name";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<HouseDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<HouseDto>>($"/{ResourceEndpoint}");
            finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);
            var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
            firstItem.Should().NotBeNull();
            firstItem.Name.Should().Be(updated.Name);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task HouseResourceSearch_FiltersByName_IsOk()
    {
        await Authenticate();

        var name = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new HouseDto { Name = name });

        try
        {
            var results = await GetAsync<PagedResult<HouseDto>>($"/{ResourceEndpoint}?search={name}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
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

        var created = await PostAsync($"/{ResourceEndpoint}", new HouseDto { Name = System.Guid.NewGuid().ToString() });

        try
        {
            var metrics = await GetAsync<HouseMetricsDto>($"/{ResourceEndpoint}/{created.Id}/metrics");
            metrics.CostHistory.Should().BeEmpty();
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
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

        var house = await PostAsync($"/{ResourceEndpoint}", new HouseDto { Name = System.Guid.NewGuid().ToString() });
        var entry = await PostAsync("/api/house-history", new HouseHistoryDto
        {
            HouseId = house.Id!,
            HistoryDate = System.DateOnly.FromDateTime(System.DateTime.Today),
            EventType = HouseEventType.Maintenance
        });

        await DeleteAsync($"/{ResourceEndpoint}/{house.Id}");

        await GetAsync($"/api/house-history/{entry.Id}", HttpStatusCode.NotFound);
    }
}
