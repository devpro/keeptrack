using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="ILeaseRepository"/> against real MongoDB - the mutual exclusion rests on the
/// server's own _id uniqueness under a filtered upsert, which only a real database can prove (a mock
/// would just restate the implementation). Each test uses its own lease name, so parallel test runs
/// can't contend with each other.
/// <para>
/// <see cref="ILeaseRepository"/> deliberately has no release/delete method (a lease is released by
/// expiring, which is what makes it safe when a holder dies), so the acquired documents are removed
/// straight from the collection instead - otherwise every run permanently adds a row to <c>lease</c>.
/// </para>
/// </summary>
public class LeaseRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task TryAcquire_WinsOnce_AndBlocksASecondHolderWhileLive()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = NewLeaseName();

        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
        (await repository.TryAcquireAsync(lease, "holder-b", TimeSpan.FromMinutes(5))).Should().BeFalse();
    }

    [Fact]
    public async Task TryAcquire_RenewsForTheCurrentHolder()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = NewLeaseName();

        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
    }

    [Fact]
    public async Task TryAcquire_SucceedsForANewHolder_OnceTheLeaseHasExpired()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = NewLeaseName();

        // a negative duration writes an already-expired lease - no sleeping in the test
        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromSeconds(-1))).Should().BeTrue();

        (await repository.TryAcquireAsync(lease, "holder-b", TimeSpan.FromMinutes(5))).Should().BeTrue();
    }

    /// <summary>
    /// The lease name is the document's <c>_id</c>, so registering it up front cleans up whichever of the
    /// acquisitions below actually created the document.
    /// </summary>
    private string NewLeaseName()
    {
        var lease = $"test-lease-{Guid.NewGuid():N}";
        TrackDocument("lease", lease);
        return lease;
    }
}
