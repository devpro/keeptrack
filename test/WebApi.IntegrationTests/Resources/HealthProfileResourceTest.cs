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
/// Full-cycle CRUD coverage for <c>HealthProfile</c> plus the two behaviors specific to the health
/// feature: the metrics endpoint (yearly costs, last visits, pending reimbursements over real MongoDB
/// data) and the cascade delete of the profile's journal - same shape as <see cref="HouseResourceTest"/>.
/// </summary>
public class HealthProfileResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/health-profiles";
    private const string RecordEndpoint = "api/health-records";

    [Fact]
    public async Task HealthProfileResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var created = await PostAsync($"/{ResourceEndpoint}", new HealthProfileDto { Name = $"Profile-{Guid.NewGuid():N}" });
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Notes = "Allergic to penicillin";
            created.ImageUrl = "https://example.com/profile.jpg";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<HealthProfileDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task HealthProfileMetrics_ComputeCostsLastVisitsAndUnbalanced_FromRealRecords()
    {
        await Authenticate();

        var profile = await PostAsync($"/{ResourceEndpoint}", new HealthProfileDto { Name = $"Profile-{Guid.NewGuid():N}" });

        try
        {
            // a fully settled appointment (price = ameli + mutuelle + leftover), an unsettled one, and a
            // sickness entry with no money
            await PostAsync($"/{RecordEndpoint}", new HealthRecordDto
            {
                HealthProfileId = profile.Id!,
                HistoryDate = new DateTime(2026, 2, 3, 9, 30, 0),
                EventType = HealthEventType.Appointment,
                Specialty = "généraliste",
                Practitioner = "Dr Martin",
                Price = 30,
                PublicReimbursement = 20,
                InsuranceReimbursement = 8.5,
                NotCovered = 1.5
            });
            await PostAsync($"/{RecordEndpoint}", new HealthRecordDto
            {
                HealthProfileId = profile.Id!,
                HistoryDate = new DateTime(2026, 5, 10, 14, 0, 0),
                EventType = HealthEventType.Appointment,
                Specialty = "dentiste",
                Practitioner = "Dr Diaz",
                Price = 120
            });
            await PostAsync($"/{RecordEndpoint}", new HealthRecordDto
            {
                HealthProfileId = profile.Id!,
                HistoryDate = new DateTime(2026, 7, 1, 8, 0, 0),
                EventType = HealthEventType.Sickness,
                Description = "Fever"
            });

            var metrics = await GetAsync<HealthMetricsDto>($"/{ResourceEndpoint}/{profile.Id}/metrics");

            var year = metrics.CostHistory.Should().ContainSingle().Subject;
            year.Year.Should().Be(2026);
            year.TotalPaid.Should().Be(150);
            year.TotalReimbursed.Should().Be(28.5);
            year.OutOfPocket.Should().Be(121.5);

            metrics.LastVisits.Should().HaveCount(2);
            metrics.LastVisits[0].Specialty.Should().Be("dentiste");

            var unbalanced = metrics.UnbalancedRecords.Should().ContainSingle().Subject;
            unbalanced.Label.Should().Be("Dr Diaz");
            unbalanced.Price.Should().Be(120);
            unbalanced.MissingAmount.Should().Be(120);
        }
        finally
        {
            // deleting the profile cascades to its records (verified below), so no per-record cleanup here
            await DeleteAsync($"/{ResourceEndpoint}/{profile.Id}");
        }
    }

    [Fact]
    public async Task DeletingAProfile_CascadesToItsJournal()
    {
        await Authenticate();

        var profile = await PostAsync($"/{ResourceEndpoint}", new HealthProfileDto { Name = $"Profile-{Guid.NewGuid():N}" });
        var record = await PostAsync($"/{RecordEndpoint}", new HealthRecordDto
        {
            HealthProfileId = profile.Id!,
            HistoryDate = DateTime.Today,
            EventType = HealthEventType.Other,
            Description = "Cascade target"
        });

        await DeleteAsync($"/{ResourceEndpoint}/{profile.Id}");

        await GetAsync($"/{RecordEndpoint}/{record.Id}", HttpStatusCode.NotFound);
    }
}
