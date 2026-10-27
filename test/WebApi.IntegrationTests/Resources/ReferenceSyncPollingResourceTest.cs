using System;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The slow half of the sync lifecycle: polling until the job reports Completed with a result.
/// Opt-in through REFERENCE_SYNC_POLL_ENABLED=true (see CONTRIBUTING.md), run on demand when touching the sync pipeline.
/// Forced, since it drives the whole pipeline against the live providers, and the default pass can find nothing to do.
/// <para>
/// It is the one test wanting the real pass, so it has its own class on the ordinary <see cref="KestrelWebAppFactory{TEntryPoint}"/>,
/// while <see cref="ReferenceDataAdminResourceTest"/> runs on <see cref="ProviderlessWebAppFactory"/>.
/// A live pass rewrites the shared Explore ranking after the test ends, which nothing can register for cleanup, so <see cref="ServerDerivedDataSweep"/> removes it.
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
