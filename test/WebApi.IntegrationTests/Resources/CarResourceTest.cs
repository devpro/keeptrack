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
/// Basic full-cycle CRUD coverage for <c>Car</c> - closes the "Car has no controller or Blazor page" /
/// "no CRUD integration test" findings tracked in docs/findings/by-design-and-gaps.md, same shape as
/// <see cref="VideoGameResourceTest"/>.
/// </summary>
public class CarResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/cars";

    [Fact]
    public async Task CarResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<CarDto>()
            .Rules((f, o) =>
            {
                o.Name = f.Random.AlphaNumeric(14);
                o.Manufacturer = f.Vehicle.Manufacturer();
                o.Model = f.Vehicle.Model();
                o.Year = f.Random.Int(1990, 2024);
                o.LicensePlate = f.Random.AlphaNumeric(8);
                o.EnergyType = CarEnergyType.Combustion;
                o.ImageUrl = f.Internet.Url();
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Name = "New shiny name";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<CarDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<CarDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Name.Should().Be(updated.Name);
    }

    /// <summary>
    /// CarRepository previously had no GetFilter override at all, so search silently fell back to the base
    /// class's $text query against an index that didn't even cover Car's field name (see
    /// docs/findings/persistence-and-mapping.md) - this proves a name search now actually finds the car.
    /// </summary>
    [Fact]
    public async Task CarResourceSearch_FiltersByName_IsOk()
    {
        await Authenticate();

        var name = Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", new CarDto { Name = name });

        var results = await GetAsync<PagedResult<CarDto>>($"/{ResourceEndpoint}?search={name}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
    }

    [Fact]
    public async Task CarResourceMetrics_ReturnsNotFound_ForACarThatDoesNotExist()
    {
        await Authenticate();

        // a freshly generated, syntactically valid ObjectId that can't collide with any real document - a
        // malformed id (e.g. a GUID) throws a MongoDB BSON FormatException instead of a clean 404, a
        // pre-existing gap in MongoDbRepositoryBase shared by every entity type, not something introduced by
        // Car; out of scope to fix here. (A fixed all-zeros id was tried first and turned out to already
        // exist as fixture data in the shared integration test database, masking the actual check.)
        await GetAsync($"/{ResourceEndpoint}/{MongoDB.Bson.ObjectId.GenerateNewId()}/metrics", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task CarResourceMetrics_ReturnsEmptyMetrics_ForACarWithNoHistoryYet()
    {
        await Authenticate();

        var created = await CreateAsync($"/{ResourceEndpoint}", new CarDto { Name = Guid.NewGuid().ToString() });

        var metrics = await GetAsync<CarMetricsDto>($"/{ResourceEndpoint}/{created.Id}/metrics");
        metrics.FuelConsumption.Should().BeEmpty();
        metrics.ElectricConsumption.Should().BeEmpty();
        metrics.CostHistory.Should().BeEmpty();
        metrics.MileageWarnings.Should().BeEmpty();
        metrics.LastRecords.Should().BeEmpty();
    }

    /// <summary>
    /// CarHistory is a separate top-level collection referencing its car by id (see AGENTS.md's "Child entities" section).
    /// Without CarController.OnDeletedAsync cascading the delete, a deleted car's history would be orphaned in MongoDB forever, only ever reachable via the now-gone car id.
    /// Same shape as <see cref="HouseResourceTest.HouseResourceDelete_CascadesToItsHistory_IsOk"/>.
    /// </summary>
    [Fact]
    public async Task CarResourceDelete_CascadesToItsHistory_IsOk()
    {
        await Authenticate();

        // both are registered even though the delete below is the point of the test: if the cascade is ever broken, the orphaned history entry is exactly what would otherwise be left behind.
        var car = await CreateAsync($"/{ResourceEndpoint}", new CarDto { Name = Guid.NewGuid().ToString() });
        var entry = await CreateAsync("/api/car-history", new CarHistoryDto
        {
            CarId = car.Id!,
            HistoryDate = DateTime.Today,
            EventType = CarHistoryType.Maintenance
        });

        await DeleteAsync($"/{ResourceEndpoint}/{car.Id}");

        await GetAsync($"/api/car-history/{entry.Id}", HttpStatusCode.NotFound);
    }
}
