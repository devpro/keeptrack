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
/// Basic full-cycle CRUD coverage for <c>HealthRecord</c>, same shape as
/// <see cref="HouseHistoryResourceTest"/> - including the date+time round trip (HistoryDate is a full
/// DateTime here, the Car pattern, so the time of day must survive MongoDB's UTC stamping).
/// </summary>
public class HealthRecordResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/health-records";

    private static HealthRecordDto NewEntry(string profileId) => new()
    {
        HealthProfileId = profileId,
        HistoryDate = new DateTime(2026, 3, 12, 16, 45, 0),
        EventType = HealthEventType.Appointment,
        Specialty = "dermatologue",
        Practitioner = "Dr Test",
        Description = "Test entry",
        Price = 51.7
    };

    [Fact]
    public async Task HealthRecordResourceFullCycle_IsOk_AndKeepsTheTimeOfDay()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var profileId = Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", NewEntry(profileId));
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.PublicReimbursement = 30;
            created.InsuranceReimbursement = 15.5;
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<HealthRecordDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);
            // the appointment's time of day is real data and must survive the BSON round trip
            updated.HistoryDate.Hour.Should().Be(16);
            updated.HistoryDate.Minute.Should().Be(45);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task HealthRecordFilter_ByProfileIdAndSearch_OnlyReturnsMatchingEntries_IsOk()
    {
        await Authenticate();

        var profileId = Guid.NewGuid().ToString();
        var otherProfileId = Guid.NewGuid().ToString();
        var practitioner = $"Dr {Guid.NewGuid():N}";
        var entry = NewEntry(profileId);
        entry.Practitioner = practitioner;
        var created = await PostAsync($"/{ResourceEndpoint}", entry);
        var otherCreated = await PostAsync($"/{ResourceEndpoint}", NewEntry(otherProfileId));

        try
        {
            var byProfile = await GetAsync<PagedResult<HealthRecordDto>>($"/{ResourceEndpoint}?HealthProfileId={profileId}");
            byProfile.Items.Should().ContainSingle(x => x.Id == created.Id);
            byProfile.Items.Should().NotContain(x => x.Id == otherCreated.Id);

            // search spans practitioner (and specialty/description) - "when did I last see Dr X"
            var bySearch = await GetAsync<PagedResult<HealthRecordDto>>($"/{ResourceEndpoint}?HealthProfileId={profileId}&search={practitioner}");
            bySearch.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{otherCreated.Id}");
        }
    }
}
