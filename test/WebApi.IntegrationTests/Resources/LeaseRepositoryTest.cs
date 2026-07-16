using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="ILeaseRepository"/> against real MongoDB - the mutual exclusion rests on the
/// server's own _id uniqueness under a filtered upsert, which only a real database can prove (a mock
/// would just restate the implementation). Each test uses its own lease name, so parallel test runs
/// can't contend with each other.
/// </summary>
public class LeaseRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task TryAcquire_WinsOnce_AndBlocksASecondHolderWhileLive()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = $"test-lease-{Guid.NewGuid():N}";

        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
        (await repository.TryAcquireAsync(lease, "holder-b", TimeSpan.FromMinutes(5))).Should().BeFalse();
    }

    [Fact]
    public async Task TryAcquire_RenewsForTheCurrentHolder()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = $"test-lease-{Guid.NewGuid():N}";

        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromMinutes(5))).Should().BeTrue();
    }

    [Fact]
    public async Task TryAcquire_SucceedsForANewHolder_OnceTheLeaseHasExpired()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
        var lease = $"test-lease-{Guid.NewGuid():N}";

        // a negative duration writes an already-expired lease - no sleeping in the test
        (await repository.TryAcquireAsync(lease, "holder-a", TimeSpan.FromSeconds(-1))).Should().BeTrue();

        (await repository.TryAcquireAsync(lease, "holder-b", TimeSpan.FromMinutes(5))).Should().BeTrue();
    }
}
