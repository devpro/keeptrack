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
/// Basic full-cycle CRUD coverage for <c>Episode</c> over HTTP, complementing <see cref="EpisodeRepositoryTest"/>'s repository-level <c>FindByShowIdsAsync</c> coverage, closing the "no dedicated full CRUD test of its own" half of the finding tracked in docs/findings/by-design-and-gaps.md ("Thin test coverage"), same shape as <see cref="CarHistoryResourceTest"/>.
/// </summary>
public class EpisodeResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/episodes";

    private static EpisodeDto NewEpisode(string tvShowId, int season = 1, int episode = 1) => new()
    {
        TvShowId = tvShowId,
        SeasonNumber = season,
        EpisodeNumber = episode,
        WatchedAt = DateOnly.FromDateTime(DateTime.Today),
        Notes = "Test entry"
    };

    [Fact]
    public async Task EpisodeResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        // TvShowId is a required field on EpisodeDto (same as CarHistory's required CarId), so the list endpoint can only ever be called scoped to a show; a bare, unscoped list call isn't a real scenario this app has, and ASP.NET's automatic model validation rejects it with 400 before the request even reaches the repository.
        var tvShowId = Guid.NewGuid().ToString();
        var initialItems = await GetAsync<PagedResult<EpisodeDto>>($"/{ResourceEndpoint}?TvShowId={tvShowId}");

        var created = await CreateAsync($"/{ResourceEndpoint}", NewEpisode(tvShowId));
        created.Id.Should().NotBeNullOrEmpty();

        created.Notes = "Updated notes";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<EpisodeDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<EpisodeDto>>($"/{ResourceEndpoint}?TvShowId={tvShowId}");
        finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);

        await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        await GetAsync($"/{ResourceEndpoint}/{created.Id}", HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task EpisodeResourceFilter_ByTvShowId_OnlyReturnsThatShowsEntries_IsOk()
    {
        await Authenticate();

        var tvShowId = Guid.NewGuid().ToString();
        var otherTvShowId = Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", NewEpisode(tvShowId));
        var otherCreated = await CreateAsync($"/{ResourceEndpoint}", NewEpisode(otherTvShowId));

        var results = await GetAsync<PagedResult<EpisodeDto>>($"/{ResourceEndpoint}?TvShowId={tvShowId}");
        results.Items.Should().ContainSingle(x => x.Id == created.Id);
        results.Items.Should().NotContain(x => x.Id == otherCreated.Id);
    }
}
