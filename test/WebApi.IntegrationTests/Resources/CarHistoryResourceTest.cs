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
/// Full-cycle CRUD coverage for <c>CarHistory</c>, plus the <c>GetFilter</c> case of docs/data-model.md.
/// A <c>CarId</c> filter and a free-text search must not both be <c>$text</c> expressions, since MongoDB rejects two in one query.
/// </summary>
public class CarHistoryResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/car-history";

    private static CarHistoryDto NewEntry(string carId, CarHistoryType eventType = CarHistoryType.Refuel) => new()
    {
        CarId = carId,
        HistoryDate = DateTime.Today,
        EventType = eventType,
        Mileage = 1000,
        Cost = 42.5,
        Description = "Test entry"
    };

    [Fact]
    public async Task CarHistoryResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        // CarId is required on CarHistoryDto, like Episode's TvShowId, so the list endpoint is always scoped to a car, as CarDetail.razor calls it.
        // ASP.NET's model validation rejects an unscoped call with 400 ("The CarId field is required") before it reaches the repository.
        var carId = Guid.NewGuid().ToString();
        var initialItems = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");

        var created = await CreateAsync($"/{ResourceEndpoint}", NewEntry(carId));
        created.Id.Should().NotBeNullOrEmpty();

        created.Cost = 55.0;
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<CarHistoryDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");
        finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);
    }

    [Fact]
    public async Task CarHistoryResourceFilter_ByCarId_OnlyReturnsThatCarsEntries_IsOk()
    {
        await Authenticate();

        var carId = Guid.NewGuid().ToString();
        var otherCarId = Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", NewEntry(carId));
        var otherCreated = await CreateAsync($"/{ResourceEndpoint}", NewEntry(otherCarId));

        var results = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
        results.Items.Should().NotContain(x => x.Id == otherCreated.Id);
    }

    /// <summary>
    /// A CarId filter and a free-text search together must not throw "only one $text expression allowed per query".
    /// </summary>
    [Fact]
    public async Task CarHistoryResourceFilter_ByCarIdAndSearch_DoesNotThrow_IsOk()
    {
        await Authenticate();

        var carId = Guid.NewGuid().ToString();
        var description = Guid.NewGuid().ToString();
        var entry = NewEntry(carId);
        entry.Description = description;
        var created = await CreateAsync($"/{ResourceEndpoint}", entry);

        var results = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}&search={description}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
    }
}
