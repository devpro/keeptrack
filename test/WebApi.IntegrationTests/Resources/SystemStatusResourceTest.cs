using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers the admin "System" panel's endpoint. Admin-gating is exercised the same way as
/// <see cref="ReferenceDataAdminResourceTest"/> (the standard test user carries the admin claim;
/// there is no non-admin account to prove the rejection side).
/// </summary>
public class SystemStatusResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/system-status";

    [Fact]
    public async Task SystemStatus_RequiresAuthentication()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SystemStatus_ReportsTheInstanceConfigurationAndSharedState()
    {
        await Authenticate();

        var status = await GetAsync<SystemStatusDto>($"/{ResourceEndpoint}");

        status.InstanceName.Should().NotBeNullOrEmpty();
        // the test host overrides Features:IsReferenceSyncEnabled to false (see KestrelWebAppFactory) -
        // asserting it here proves the endpoint reflects live configuration, not a default
        status.IsReferenceSyncEnabled.Should().BeFalse();
        status.BookProvider.Should().NotBeNullOrEmpty();
        status.RecentJobs.Should().NotBeNull();
    }

    [Fact]
    public async Task SystemStatus_ListsAJobStartedThroughTheApi()
    {
        await Authenticate();

        // starting a sync job (its store is shared with imports) must surface in the recent-jobs list
        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();

        var status = await GetAsync<SystemStatusDto>($"/{ResourceEndpoint}");

        status.RecentJobs.Should().Contain(j => j.Kind == "ReferenceSync");
    }
}
