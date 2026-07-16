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
    /// Exercises the "sync now" job start over HTTP: POST returns immediately (202 + job id) rather than
    /// blocking on every reference document - the actual fix for the timeout reported against this
    /// endpoint (see docs/code-quality-findings.md) - and the status endpoint reports the job it started.
    /// The poll-to-completion half lives in <see cref="SyncNow_PollingReachesACompletedResult"/>, opt-in,
    /// because its duration is unbounded by this repo (it re-checks every reference document against the
    /// live providers, so it grows with the shared database and flakes on provider latency/rate limits).
    /// </summary>
    [Fact]
    public async Task SyncNow_StartsAJob_AndStatusIsQueryable()
    {
        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();

        var status = await GetAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{job.JobId}");
        status.Stage.Should().NotBe(ReferenceSyncStage.Failed, status.ErrorMessage);
    }

    /// <summary>
    /// The slow half of the lifecycle: polling until the job reports Completed with a result. Opt-in via
    /// REFERENCE_SYNC_POLL_ENABLED=true (see CONTRIBUTING.md) - run it on demand when touching the sync
    /// pipeline, not on every default test run.
    /// </summary>
    [Fact]
    public async Task SyncNow_PollingReachesACompletedResult()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("REFERENCE_SYNC_POLL_ENABLED") == "true",
            "REFERENCE_SYNC_POLL_ENABLED is not set; the poll-to-completion sync test is opt-in.");

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
