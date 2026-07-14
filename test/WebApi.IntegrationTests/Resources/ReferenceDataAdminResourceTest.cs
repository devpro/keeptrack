using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The standard test user carries the Firebase <c>role: admin</c> custom claim (see CONTRIBUTING.md's
/// "Admin role" section), so admin-gated endpoints can be exercised end-to-end over HTTP with the same
/// single test account - there's no separate non-admin account to prove the "AdminOnly" policy actually
/// rejects a non-admin caller.
/// </summary>
public class ReferenceDataAdminResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private static readonly TimeSpan PollTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    [Fact]
    public async Task GetUnresolved_WithAdminRole_IsOk()
    {
        await Authenticate();

        await GetAsync<List<UnresolvedReferenceDto>>("/api/reference-data/unresolved?type=TvShow");
    }

    /// <summary>
    /// Exercises the full "sync now" background job lifecycle over HTTP: POST starts the job and returns
    /// immediately (202 + job id) rather than blocking on every reference document, then polling GET
    /// reaches a terminal stage with a result - the actual fix for the timeout reported against this
    /// endpoint (see docs/code-quality-findings.md).
    /// </summary>
    [Fact]
    public async Task SyncNow_StartsAJob_AndPollingReachesACompletedResult()
    {
        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();

        var deadline = DateTime.UtcNow + PollTimeout;
        ReferenceSyncJobStatusDto status;
        do
        {
            status = await GetAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{job.JobId}");
            if (status.Stage is ReferenceSyncStage.Completed or ReferenceSyncStage.Failed) break;
            await Task.Delay(PollInterval, TestContext.Current.CancellationToken);
        } while (DateTime.UtcNow < deadline);

        status.Stage.Should().Be(ReferenceSyncStage.Completed, status.ErrorMessage);
        status.Result.Should().NotBeNull();
    }

    [Fact]
    public async Task SyncNowStatus_ForAnUnknownJobId_IsNotFound()
    {
        await Authenticate();

        await GetAsync($"/api/reference-data/sync-now/{Guid.NewGuid()}", HttpStatusCode.NotFound);
    }
}
