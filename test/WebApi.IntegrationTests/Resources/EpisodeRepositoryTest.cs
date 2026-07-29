using System;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="IEpisodeRepository.FindByShowIdsAsync"/> against real MongoDB. This is the batched,
/// owner-scoped multi-show read Watch Next uses instead of pulling the whole owner's episode history and
/// discarding non-current shows in memory - verified against a real database, not mocks, since it's a
/// hand-written Mongo filter (the class of code that has hidden bugs before, see docs/code-quality-findings.md).
/// </summary>
public class EpisodeRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindByShowIdsAsync_ReturnsOnlyTheRequestedShowsEpisodes_ScopedToTheOwner()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IEpisodeRepository>();
        var ownerId = $"owner-{Guid.NewGuid()}";
        var otherOwnerId = $"owner-{Guid.NewGuid()}";
        var wantedShowId = $"show-{Guid.NewGuid()}";
        var otherShowId = $"show-{Guid.NewGuid()}";

        var wanted = await repository.CreateAsync(NewEpisode(ownerId, wantedShowId, 1, 1));
        var wantedSecond = await repository.CreateAsync(NewEpisode(ownerId, wantedShowId, 1, 2));
        // same owner, a show that was NOT requested - must be excluded
        var unrelatedShow = await repository.CreateAsync(NewEpisode(ownerId, otherShowId, 1, 1));
        // a different owner tracking the very same show id - must be excluded (owner scoping)
        var otherOwner = await repository.CreateAsync(NewEpisode(otherOwnerId, wantedShowId, 1, 1));

        try
        {
            var found = await repository.FindByShowIdsAsync(ownerId, [wantedShowId]);

            found.Select(e => e.Id).Should().BeEquivalentTo([wanted.Id, wantedSecond.Id]);
        }
        finally
        {
            foreach (var id in new[] { wanted.Id!, wantedSecond.Id!, unrelatedShow.Id!, otherOwner.Id! })
            {
                await repository.DeleteAsync(id, id == otherOwner.Id ? otherOwnerId : ownerId);
            }
        }
    }

    [Fact]
    public async Task FindByShowIdsAsync_ReturnsEmpty_WhenNoShowIdsAreGiven()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IEpisodeRepository>();

        var found = await repository.FindByShowIdsAsync($"owner-{Guid.NewGuid()}", []);

        found.Should().BeEmpty();
    }

    private static EpisodeModel NewEpisode(string ownerId, string showId, int season, int episode) => new()
    {
        OwnerId = ownerId,
        TvShowId = showId,
        SeasonNumber = season,
        EpisodeNumber = episode,
        WatchedAt = DateOnly.FromDateTime(DateTime.Today)
    };
}
