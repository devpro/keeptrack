using System;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The slow half of the sync lifecycle: polling until the job reports Completed with a result. Opt-in via
/// REFERENCE_SYNC_POLL_ENABLED=true (see CONTRIBUTING.md) - run it on demand when touching the sync pipeline,
/// not on every default test run. Forced on purpose: the point is to drive the whole pipeline against the live
/// providers, and the default pass can legitimately find nothing to do.
/// <para>
/// It sits in its own class precisely because of that: it is the one test here that *wants* the real pass, so
/// it keeps the ordinary <see cref="KestrelWebAppFactory{TEntryPoint}"/> while the endpoint-contract tests in
/// <see cref="ReferenceDataAdminResourceTest"/> moved to <see cref="ProviderlessWebAppFactory"/>. A live pass
/// rewrites the shared Explore ranking, which nothing can register for cleanup at creation time (the pass
/// writes it after the test ends) - <see cref="ServerDerivedDataSweep"/> is what removes it, and it only ever
/// has work to do because of this test.
/// </para>
/// </summary>
public class ReferenceSyncPollingResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private static readonly TimeSpan PollTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    [Fact]
    public async Task SyncNow_PollingReachesACompletedResult()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("REFERENCE_SYNC_POLL_ENABLED") == "true",
            "REFERENCE_SYNC_POLL_ENABLED is not set; the poll-to-completion sync test is opt-in.");

        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now?force=true", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();
        TrackDocument("background_job", job.JobId.ToString());

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
}
