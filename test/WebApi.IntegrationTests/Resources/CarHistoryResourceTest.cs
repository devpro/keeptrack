using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Basic full-cycle CRUD coverage for <c>CarHistory</c>, plus a regression test for the specific bug tracked
/// in docs/code-quality-findings.md: <c>CarHistoryRepository.GetFilter</c> used to combine two <c>$text</c>
/// expressions (one for <c>CarId</c>, one for the free-text search) in a single query, which MongoDB rejects
/// whenever both are supplied at once.
/// </summary>
public class CarHistoryResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/car-history";

    private static CarHistoryDto NewEntry(string carId, CarHistoryType eventType = CarHistoryType.Refuel) => new()
    {
        CarId = carId,
        HistoryDate = DateOnly.FromDateTime(DateTime.Today),
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

        // CarId is a required field on CarHistoryDto, so - same as Episode's required TvShowId - the list
        // endpoint can only ever be called scoped to a car; a bare, unscoped list call isn't a real scenario
        // this app has (CarDetail.razor always filters by CarId), and ASP.NET's automatic model validation
        // rejects it with 400 ("The CarId field is required") before the request even reaches the repository.
        var carId = Guid.NewGuid().ToString();
        var initialItems = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");

        var created = await PostAsync($"/{ResourceEndpoint}", NewEntry(carId));
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Cost = 55.0;
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<CarHistoryDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");
            finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task CarHistoryResourceFilter_ByCarId_OnlyReturnsThatCarsEntries_IsOk()
    {
        await Authenticate();

        var carId = Guid.NewGuid().ToString();
        var otherCarId = Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", NewEntry(carId));
        var otherCreated = await PostAsync($"/{ResourceEndpoint}", NewEntry(otherCarId));

        try
        {
            var results = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
            results.Items.Should().NotContain(x => x.Id == otherCreated.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{otherCreated.Id}");
        }
    }

    /// <summary>
    /// The actual regression case: supplying both a CarId filter and a free-text search at the same time used
    /// to throw ("only one $text expression allowed per query") because both were built as $text clauses.
    /// </summary>
    [Fact]
    public async Task CarHistoryResourceFilter_ByCarIdAndSearch_DoesNotThrow_IsOk()
    {
        await Authenticate();

        var carId = Guid.NewGuid().ToString();
        var description = Guid.NewGuid().ToString();
        var entry = NewEntry(carId);
        entry.Description = description;
        var created = await PostAsync($"/{ResourceEndpoint}", entry);

        try
        {
            var results = await GetAsync<PagedResult<CarHistoryDto>>($"/{ResourceEndpoint}?CarId={carId}&search={description}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
