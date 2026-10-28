using System;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="ITvShowRepository.FindFinishedLinkedShowsAsync"/> against real MongoDB, the query deciding which shows the status reconciliation may reopen.
/// Null storage and the empty-string sentinel are MongoDB semantics a mocked repository cannot prove.
/// </summary>
public class TvShowRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindFinishedLinkedShowsAsync_ReturnsOnlyFinishedShowsWithARealReference_AcrossOwners()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowRepository>();
        var ownerId = $"owner-{Guid.NewGuid()}";
        var otherOwnerId = $"owner-{Guid.NewGuid()}";
        var referenceId = ObjectId.GenerateNewId().ToString();

        var finished = await CreateShowAsync(repository, ownerId, TvShowStatus.Finished, referenceId);
        var otherOwnersFinished = await CreateShowAsync(repository, otherOwnerId, TvShowStatus.Finished, referenceId);
        var current = await CreateShowAsync(repository, ownerId, TvShowStatus.Current, referenceId);
        var stopped = await CreateShowAsync(repository, ownerId, TvShowStatus.Stopped, referenceId);
        var unset = await CreateShowAsync(repository, ownerId, null, referenceId);
        var unlinked = await CreateShowAsync(repository, ownerId, TvShowStatus.Finished, null);
        var emptySentinel = await CreateShowAsync(repository, ownerId, TvShowStatus.Finished, string.Empty);

        var found = (await repository.FindFinishedLinkedShowsAsync()).Select(s => s.Id).ToList();

        found.Should().Contain([finished.Id, otherOwnersFinished.Id]);
        found.Should().NotContain([current.Id, stopped.Id, unset.Id, unlinked.Id, emptySentinel.Id]);
    }

    private async Task<TvShowModel> CreateShowAsync(ITvShowRepository repository, string ownerId, TvShowStatus? state, string? referenceId)
    {
        var created = await repository.CreateAsync(new TvShowModel
        {
            OwnerId = ownerId,
            Title = $"The Diplomat {Guid.NewGuid()}",
            State = state,
            ReferenceId = referenceId
        });
        TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
        return created;
    }
}
