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
/// The standard test user carries the Firebase <c>role: admin</c> custom claim (see CONTRIBUTING.md's "Admin role" section), so admin-gated endpoints run end to end over HTTP with the single test account.
/// There is no separate non-admin account to prove the "AdminOnly" policy rejects a non-admin caller.
/// <para>
/// Hosted through <see cref="ProviderlessWebAppFactory"/>: nothing here asserts what a provider returns, but three tests start a real <c>sync-now</c> job.
/// Against live providers it would run on after the test, rewriting the shared Explore ranking, mutating reference documents and spending OMDb's daily budget (see that fixture).
/// </para>
/// </summary>
public class ReferenceDataAdminResourceTest(ProviderlessWebAppFactory factory)
    : ResourceTestBase(factory), IClassFixture<ProviderlessWebAppFactory>
{
    [Fact]
    public async Task GetUnresolved_WithAdminRole_IsOk()
    {
        await Authenticate();

        await GetAsync<List<UnresolvedReferenceDto>>("/api/reference-data/unresolved?type=TvShow");
    }

    /// <summary>
    /// Registration order in Program.cs is the admin picker's display order (<c>ReferenceClientRegistry.All</c> preserves it): Google Books is the default, then Open Library and BnF.
    /// This pins the contract, so a reordering in Program.cs fails a test instead of silently changing the picker.
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
        providers.Single(p => p.Key == "googlebooks").IsDefault.Should().BeTrue();
        providers.Where(p => p.Key != "googlebooks").Should().OnlyContain(p => !p.IsDefault);
    }

    [Fact]
    public async Task GetProviders_ReturnsRegisteredVideoGameProvidersInPriorityOrder()
    {
        // IGDB first because it is the deployment default; RAWG stays registered so references linked through it keep their stored ratings.
        await Authenticate();

        var providers = await GetAsync<List<ReferenceProviderDto>>("/api/reference-data/providers?type=VideoGame");

        providers.Select(p => p.Key).Should().Equal("igdb", "rawg");
        providers.Single(p => p.Key == "igdb").IsDefault.Should().BeTrue();
        providers.Single(p => p.Key == "rawg").IsDefault.Should().BeFalse();
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
    /// Exercises the "sync now" job start over HTTP: POST returns at once (202 and a job id) rather than blocking on every reference document, and the status endpoint reports the job it started.
    /// The poll-to-completion half is <see cref="SyncNow_PollingReachesACompletedResult"/>, opt-in, since it re-checks every reference against the live providers and grows with the shared database.
    /// No <c>force</c> here, so this is the default incremental pass, the documents the periodic tick would take.
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
    /// The forced variant: <c>?force=true</c> re-checks every document regardless of age, where the default takes only what the periodic pass would (see <c>ReferenceSyncWindows</c>).
    /// Both are the same job over the same endpoint, so this only pins that the parameter is accepted and starts a real job.
    /// What each mode selects is covered by <c>ReferenceSyncWindowsTest</c>, and the query itself by <c>ReferenceStalenessRepositoryTest</c>.
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
    /// The Explore-only variant: <c>?exploreOnly=true</c> rebuilds the discovery rankings and skips the five reference domains entirely.
    /// It asserts the part that can fail silently: the job starts and stays in the Explore stage rather than walking the reference stages.
    /// "It skipped the expensive half" and "it ran the expensive half quickly" look identical from a 202 alone.
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

        // A ranking rebuild is bounded (a few listing pages per ordering), so Completed is a legitimate answer by this poll, but a reference stage never is.
        status.Stage.Should()
            .BeOneOf([ReferenceSyncStage.RefreshingExplore, ReferenceSyncStage.Completed], because: status.ErrorMessage ?? "");
    }

    [Fact]
    public async Task SyncNowStatus_ForAnUnknownJobId_IsNotFound()
    {
        await Authenticate();

        await GetAsync($"/api/reference-data/sync-now/{Guid.NewGuid()}", HttpStatusCode.NotFound);
    }
}
