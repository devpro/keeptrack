using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Infrastructure.MongoDb.Entities;
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
    /// Registration order in Program.cs doubles as the admin UI's provider-picker display/priority order
    /// (<c>ReferenceClientRegistry.All</c> preserves it) - Google Books is the default, Open Library and
    /// BnF are fallbacks in that order. This pins the contract so a future reordering in Program.cs fails a
    /// test instead of silently changing the picker's default.
    /// </summary>
    [Fact]
    public async Task GetProviders_ReturnsRegisteredBookProvidersInPriorityOrder()
    {
        await Authenticate();

        var providers = await GetAsync<List<ReferenceProviderDto>>("/api/reference-data/providers?type=Book");

        providers.Select(p => p.Key).Should().Equal("googlebooks", "openlibrary", "bnf");
        providers.Should().Contain(p => p.Key == "googlebooks" && p.DisplayName == "Google Books");
        providers.Should().Contain(p => p.Key == "openlibrary" && p.DisplayName == "Open Library");
        providers.Should().Contain(p => p.Key == "bnf" && p.DisplayName == "BnF");
    }

    [Fact]
    public async Task GetProviders_ReturnsRegisteredVideoGameProvidersInPriorityOrder()
    {
        // IGDB first because it is the deployment default; RAWG stays registered so references linked through
        // it keep their stored ratings.
        await Authenticate();

        var providers = await GetAsync<List<ReferenceProviderDto>>("/api/reference-data/providers?type=VideoGame");

        providers.Select(p => p.Key).Should().Equal("igdb", "rawg");
    }

    [Fact]
    public async Task GetProviders_ReturnsNothing_ForASingleProviderDomain()
    {
        // an empty list is what tells the admin UI not to render a picker at all
        await Authenticate();

        var providers = await GetAsync<List<ReferenceProviderDto>>("/api/reference-data/providers?type=Movie");

        providers.Should().BeEmpty();
    }

    /// <summary>
    /// Exercises the "sync now" job start over HTTP: POST returns immediately (202 + job id) rather than
    /// blocking on every reference document - the actual fix for the timeout reported against this
    /// endpoint (see docs/code-quality-findings.md) - and the status endpoint reports the job it started.
    /// The poll-to-completion half lives in <see cref="SyncNow_PollingReachesACompletedResult"/>, opt-in,
    /// because its duration is unbounded by this repo (it re-checks every reference document against the
    /// live providers, so it grows with the shared database and flakes on provider latency/rate limits).
    /// No <c>force</c> here, so this is the default incremental pass - the same documents the periodic
    /// background tick would take.
    /// </summary>
    [Fact]
    public async Task SyncNow_StartsAJob_AndStatusIsQueryable()
    {
        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();
        // the job row would otherwise sit in the admin panel's recent-jobs list until the TTL index expires it
        TrackDocument("background_job", job.JobId.ToString());

        var status = await GetAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{job.JobId}");
        status.Stage.Should().NotBe(ReferenceSyncStage.Failed, status.ErrorMessage);
    }

    /// <summary>
    /// The forced variant: <c>?force=true</c> re-checks every document regardless of age, where the default
    /// takes only what the periodic pass would (see <c>ReferenceSyncWindows</c>). Both are the same job over
    /// the same endpoint, so this only pins that the parameter is accepted and still starts a real job -
    /// what each mode selects is covered by <c>ReferenceSyncWindowsTest</c> and, for the query itself, by
    /// <c>ReferenceStalenessRepositoryTest</c>.
    /// </summary>
    [Fact]
    public async Task SyncNow_WithForce_StartsAJob_AndStatusIsQueryable()
    {
        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now?force=true", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();
        TrackDocument("background_job", job.JobId.ToString());

        var status = await GetAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{job.JobId}");
        status.Stage.Should().NotBe(ReferenceSyncStage.Failed, status.ErrorMessage);
    }

    /// <summary>
    /// The Explore-only variant: <c>?exploreOnly=true</c> rebuilds the discovery rankings and skips the five
    /// reference domains entirely. What is asserted is the part that can go wrong silently - the job starts in
    /// (and stays in) the Explore stage rather than walking the reference stages first, since "it skipped the
    /// expensive half" and "it ran the expensive half quickly" look identical from a 202 alone.
    /// </summary>
    [Fact]
    public async Task SyncNow_WithExploreOnly_SkipsTheReferenceStagesEntirely()
    {
        await Authenticate();

        var job = await PostAsync<ReferenceSyncJobDto?>("/api/reference-data/sync-now?exploreOnly=true", null, HttpStatusCode.Accepted);
        job.Should().NotBeNull();
        job!.JobId.Should().NotBeEmpty();
        TrackDocument("background_job", job.JobId.ToString());

        var status = await GetAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{job.JobId}");

        // a ranking rebuild is bounded (a few listing pages per ordering), so Completed is a legitimate answer
        // by the time this poll lands - but a reference stage never is.
        status.Stage.Should()
            .BeOneOf([ReferenceSyncStage.RefreshingExplore, ReferenceSyncStage.Completed], because: status.ErrorMessage ?? "");
    }

    /// <summary>
    /// The slow half of the lifecycle: polling until the job reports Completed with a result. Opt-in via
    /// REFERENCE_SYNC_POLL_ENABLED=true (see CONTRIBUTING.md) - run it on demand when touching the sync
    /// pipeline, not on every default test run. Forced on purpose: the point is to drive the whole pipeline
    /// against the live providers, and the default pass can legitimately find nothing to do.
    /// </summary>
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

    [Fact]
    public async Task SyncNowStatus_ForAnUnknownJobId_IsNotFound()
    {
        await Authenticate();

        await GetAsync($"/api/reference-data/sync-now/{Guid.NewGuid()}", HttpStatusCode.NotFound);
    }
}
