using System;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Basic full-cycle CRUD coverage for <c>HouseHistory</c>, same shape as <see cref="CarHistoryResourceTest"/>.
/// </summary>
public class HouseHistoryResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/house-history";

    private static HouseHistoryDto NewEntry(string houseId, HouseEventType eventType = HouseEventType.Maintenance) => new()
    {
        HouseId = houseId,
        HistoryDate = DateOnly.FromDateTime(DateTime.Today),
        EventType = eventType,
        Cost = 42.5,
        Description = "Test entry"
    };

    [Fact]
    public async Task HouseHistoryResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var houseId = Guid.NewGuid().ToString();
        var initialItems = await GetAsync<PagedResult<HouseHistoryDto>>($"/{ResourceEndpoint}?HouseId={houseId}");

        var created = await PostAsync($"/{ResourceEndpoint}", NewEntry(houseId));
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Cost = 55.0;
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<HouseHistoryDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<HouseHistoryDto>>($"/{ResourceEndpoint}?HouseId={houseId}");
            finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task HouseHistoryResourceFilter_ByHouseId_OnlyReturnsThatHousesEntries_IsOk()
    {
        await Authenticate();

        var houseId = Guid.NewGuid().ToString();
        var otherHouseId = Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", NewEntry(houseId));
        var otherCreated = await PostAsync($"/{ResourceEndpoint}", NewEntry(otherHouseId));

        try
        {
            var results = await GetAsync<PagedResult<HouseHistoryDto>>($"/{ResourceEndpoint}?HouseId={houseId}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
            results.Items.Should().NotContain(x => x.Id == otherCreated.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{otherCreated.Id}");
        }
    }

    [Fact]
    public async Task HouseHistoryResourceFilter_ByHouseIdAndSearch_DoesNotThrow_IsOk()
    {
        await Authenticate();

        var houseId = Guid.NewGuid().ToString();
        var description = Guid.NewGuid().ToString();
        var entry = NewEntry(houseId);
        entry.Description = description;
        var created = await PostAsync($"/{ResourceEndpoint}", entry);

        try
        {
            var results = await GetAsync<PagedResult<HouseHistoryDto>>($"/{ResourceEndpoint}?HouseId={houseId}&search={description}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
