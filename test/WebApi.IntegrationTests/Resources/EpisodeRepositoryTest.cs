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
/// Exercises <see cref="IEpisodeRepository.FindByShowIdsAsync"/> against real MongoDB.
/// It is the batched, owner-scoped multi-show read Watch Next uses rather than pulling the owner's whole episode history.
/// A hand-written Mongo filter of this kind hides bugs (see docs/data-model.md), so it is verified against a real database, not mocks.
/// </summary>
public class EpisodeRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByShowIdsAsync_ReturnsOnlyTheRequestedShowsEpisodes_ScopedToTheOwner()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IEpisodeRepository>();
        var ownerId = $"owner-{Guid.NewGuid()}";
        var otherOwnerId = $"owner-{Guid.NewGuid()}";
        var wantedShowId = $"show-{Guid.NewGuid()}";
        var otherShowId = $"show-{Guid.NewGuid()}";

        var wanted = await CreateEpisodeAsync(repository, ownerId, wantedShowId, 1, 1);
        var wantedSecond = await CreateEpisodeAsync(repository, ownerId, wantedShowId, 1, 2);
        // same owner, a show not requested, excluded
        await CreateEpisodeAsync(repository, ownerId, otherShowId, 1, 1);
        // another owner tracking the same show id, excluded by owner scoping
        await CreateEpisodeAsync(repository, otherOwnerId, wantedShowId, 1, 1);

        var found = await repository.FindByShowIdsAsync(ownerId, [wantedShowId]);

        found.Select(e => e.Id).Should().BeEquivalentTo([wanted.Id, wantedSecond.Id]);
    }

    [Fact]
    public async Task FindByShowIdsAsync_ReturnsEmpty_WhenNoShowIdsAreGiven()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IEpisodeRepository>();

        var found = await repository.FindByShowIdsAsync($"owner-{Guid.NewGuid()}", []);

        found.Should().BeEmpty();
    }

    private async Task<EpisodeModel> CreateEpisodeAsync(IEpisodeRepository repository, string ownerId, string showId, int season, int episode)
    {
        var created = await repository.CreateAsync(new EpisodeModel
        {
            OwnerId = ownerId,
            TvShowId = showId,
            SeasonNumber = season,
            EpisodeNumber = episode,
            WatchedAt = DateOnly.FromDateTime(DateTime.Today)
        });
        TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
        return created;
    }
}
