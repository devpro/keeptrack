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
/// "no CRUD integration test" findings tracked in docs/code-quality-findings.md, same shape as
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
            })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Name = "New shiny name";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<CarDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<CarDto>>($"/{ResourceEndpoint}");
            var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
            firstItem.Should().NotBeNull();
            firstItem.Name.Should().Be(updated.Name);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    /// <summary>
    /// CarRepository previously had no GetFilter override at all, so search silently fell back to the base
    /// class's $text query against an index that didn't even cover Car's field name (see
    /// docs/code-quality-findings.md) - this proves a name search now actually finds the car.
    /// </summary>
    [Fact]
    public async Task CarResourceSearch_FiltersByName_IsOk()
    {
        await Authenticate();

        var name = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new CarDto { Name = name });

        try
        {
            var results = await GetAsync<PagedResult<CarDto>>($"/{ResourceEndpoint}?search={name}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
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

        var created = await PostAsync($"/{ResourceEndpoint}", new CarDto { Name = System.Guid.NewGuid().ToString() });

        try
        {
            var metrics = await GetAsync<CarMetricsDto>($"/{ResourceEndpoint}/{created.Id}/metrics");
            metrics.FuelConsumption.Should().BeEmpty();
            metrics.ElectricConsumption.Should().BeEmpty();
            metrics.CostHistory.Should().BeEmpty();
            metrics.MileageWarnings.Should().BeEmpty();
            metrics.LastRecords.Should().BeEmpty();
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
