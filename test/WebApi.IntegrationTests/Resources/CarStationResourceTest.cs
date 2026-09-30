using System;
using System.Collections.Generic;
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
/// The shared, owner-less <c>car_station</c> catalogue, over real HTTP and real MongoDB.
/// <para>
/// A mocked repository could prove none of this: the find-or-create's whole job is to keep the collection's
/// unique natural-key index from firing, the delete guard and the merge are about what other documents
/// point at, and the display hydration is a batched read layered onto a real list response.
/// </para>
/// <para>
/// The test account carries the admin role (see <c>ReferenceDataAdminResourceTest</c>), so the admin-gated
/// half is reachable with the same single account.
/// </para>
/// </summary>
public class CarStationResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string StationsEndpoint = "api/car-stations";
    private const string HistoryEndpoint = "api/car-history";

    /// <summary>
    /// Stations are shared across accounts and de-duplicated by name, so a fixed one would collide with the
    /// last run's leftovers and with a parallel class - every test mints its own.
    /// </summary>
    private static string UniqueBrand() => $"E2e Station {Guid.NewGuid():N}";

    private async Task<CarStationDto> CreateStationAsync(string brandName, string? city = null, string? postalCode = null)
    {
        var created = await PostAsync(StationsEndpoint, new CarStationDto { BrandName = brandName, City = city, PostalCode = postalCode });
        // registered at the moment of creation, never in a later try/finally - a create that fails after
        // this one would otherwise leak a document the unique index makes the next run trip over
        TrackDocument("car_station", created.Id);
        return created;
    }

    [Fact]
    public async Task StationList_RequiresAuthentication()
    {
        await GetAsync($"/{StationsEndpoint}", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PostStation_IsFindOrCreate_AndIgnoresCasingAndPadding()
    {
        await Authenticate();

        var brand = UniqueBrand();
        var created = await CreateStationAsync(brand, "Rennes");
        created.Id.Should().NotBeNullOrEmpty();

        // The picker posts every time a member types a station that isn't in its list yet, so this has to be
        // idempotent - and it has to normalize, or "Total" and "total " become two documents describing one
        // physical place. The natural key is the same trim+lowercase the repository stamps.
        var again = await PostAsync(StationsEndpoint, new CarStationDto { BrandName = $"  {brand.ToUpperInvariant()}  ", City = "RENNES" }, HttpStatusCode.OK);
        again.Id.Should().Be(created.Id);

        var all = await GetAsync<List<CarStationDto>>($"/{StationsEndpoint}");
        all.Count(s => s.Id == created.Id).Should().Be(1);
    }

    [Fact]
    public async Task PostStation_SameBrandInAnotherCity_IsADifferentStation()
    {
        await Authenticate();

        // the city is part of the natural key precisely so two towns' Total don't collapse into one
        var brand = UniqueBrand();
        var rennes = await CreateStationAsync(brand, "Rennes");
        var nantes = await CreateStationAsync(brand, "Nantes");

        nantes.Id.Should().NotBe(rennes.Id);
    }

    [Fact]
    public async Task PostStation_WithoutABrandName_IsRejected()
    {
        await Authenticate();

        // a station with no name has no identity to de-duplicate on, so it must never reach the collection
        await PostNoContentAsync(StationsEndpoint, new CarStationDto { City = "Rennes" }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task HistoryList_HydratesTheStationNameAndCity()
    {
        await Authenticate();

        var station = await CreateStationAsync(UniqueBrand(), "Rennes");
        var carId = Guid.NewGuid().ToString();
        await CreateAsync($"/{HistoryEndpoint}", new CarHistoryDto
        {
            CarId = carId,
            HistoryDate = DateTime.Today,
            EventType = CarHistoryType.Refuel,
            FuelVolume = 42.30,
            FuelUnitPrice = 1.789,
            Cost = 75.68,
            StationId = station.Id
        });

        // the entry stores an id and nothing else; the name and city come back from the station document,
        // which is the whole point of not copying them onto every refuel
        var page = await GetAsync<PagedResult<CarHistoryDto>>($"/{HistoryEndpoint}?CarId={carId}");
        var entry = page.Items.Should().ContainSingle().Subject;
        entry.StationId.Should().Be(station.Id);
        entry.StationBrandName.Should().Be(station.BrandName);
        entry.StationCity.Should().Be("Rennes");
        // and the entry itself carries no location of its own any more
        entry.City.Should().BeNull();
    }

    [Fact]
    public async Task DeleteStation_IsRefusedWhileEntriesStillPointAtIt()
    {
        await Authenticate();

        var station = await CreateStationAsync(UniqueBrand(), "Rennes");
        var carId = Guid.NewGuid().ToString();
        var entry = await CreateAsync($"/{HistoryEndpoint}", new CarHistoryDto
        {
            CarId = carId,
            HistoryDate = DateTime.Today,
            EventType = CarHistoryType.Refuel,
            StationId = station.Id
        });

        // deleting it here would blank that refuel's location with nothing to recover it from - that's a
        // merge, not a delete
        await DeleteAsync($"/{StationsEndpoint}/{station.Id}", HttpStatusCode.Conflict);
        await GetAsync<CarStationDto>($"/{StationsEndpoint}/{station.Id}");

        // once nothing references it, the same delete goes through
        await DeleteAsync($"/{HistoryEndpoint}/{entry.Id}");
        await DeleteAsync($"/{StationsEndpoint}/{station.Id}");
        await GetAsync($"/{StationsEndpoint}/{station.Id}", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task MergeStations_RepointsEveryEntryThenRemovesTheAbsorbedOne()
    {
        await Authenticate();

        // the duplicate pair inline creation produces: the same place typed twice, one of them enriched
        var absorbed = await CreateStationAsync(UniqueBrand());
        var survivor = await CreateStationAsync(UniqueBrand(), "Rennes");

        var carId = Guid.NewGuid().ToString();
        var entry = await CreateAsync($"/{HistoryEndpoint}", new CarHistoryDto
        {
            CarId = carId,
            HistoryDate = DateTime.Today,
            EventType = CarHistoryType.Refuel,
            StationId = absorbed.Id
        });

        var result = await PostAsync<object?, CarStationMergeResultDto>($"{StationsEndpoint}/{absorbed.Id}/merge/{survivor.Id}", null, HttpStatusCode.OK);
        result.RepointedEntries.Should().Be(1);
        result.Station!.Id.Should().Be(survivor.Id);

        // re-pointed, not stranded: skipping this step is what would silently blank the entry's station
        var reread = await GetAsync<CarHistoryDto>($"/{HistoryEndpoint}/{entry.Id}");
        reread.StationId.Should().Be(survivor.Id);

        await GetAsync($"/{StationsEndpoint}/{absorbed.Id}", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task MergeStations_FillsTheSurvivorsGapsWithoutOverwritingWhatItKnows()
    {
        await Authenticate();

        // both documents describe one physical station, so a field only one of them has is new information -
        // but the survivor's own values must win, the same "never overwrite with nothing" rule as
        // SetReferenceLinkAsync
        var absorbed = await CreateStationAsync(UniqueBrand(), "Rennes", "35000");
        absorbed.Country = "FR";
        absorbed.Latitude = 48.1173;
        absorbed.Longitude = -1.6743;
        await PutAsync($"/{StationsEndpoint}/{absorbed.Id}", absorbed);

        var survivor = await CreateStationAsync(UniqueBrand(), "Nantes");

        var result = await PostAsync<object?, CarStationMergeResultDto>($"{StationsEndpoint}/{absorbed.Id}/merge/{survivor.Id}", null, HttpStatusCode.OK);

        var merged = result.Station!;
        merged.City.Should().Be("Nantes", "the survivor already knew its own city");
        merged.PostalCode.Should().Be("35000", "the survivor had none, so the absorbed one's is new information");
        merged.Country.Should().Be("FR");
        merged.Latitude.Should().BeApproximately(48.1173, 0.0001);
    }

    [Fact]
    public async Task PutStation_OntoAnotherStationsNaturalKey_IsRefusedRatherThanTrippingTheUniqueIndex()
    {
        await Authenticate();

        var brand = UniqueBrand();
        var rennes = await CreateStationAsync(brand, "Rennes");
        var cityless = await CreateStationAsync(brand);

        // giving the second one Rennes' city would put both on one natural key - the unique index would
        // reject the write as a 500, so the API has to name the collision instead
        cityless.City = "Rennes";
        await PutAsync($"/{StationsEndpoint}/{cityless.Id}", cityless, HttpStatusCode.Conflict);
    }
}
