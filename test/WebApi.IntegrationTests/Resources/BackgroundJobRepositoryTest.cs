using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="IBackgroundJobRepository"/> against real MongoDB - this store is what makes
/// job polling work across WebApi replicas (see CLAUDE.md's scaling section), so its owner-scoping
/// query and update shapes are verified against a real database, not mocks.
/// <para>
/// The <c>background_job</c> collection has a TTL index, so a leftover eventually disappears on its own -
/// but "eventually" is seven days, and until then every run adds three more rows to what an admin sees on
/// the system-status panel. The jobs are removed directly, since the repository has no delete method
/// (nothing in the application ever deletes a job; the TTL does).
/// </para>
/// </summary>
public class BackgroundJobRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task CreateUpdateCompleteAndFind_RoundTripsThroughMongo()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBackgroundJobRepository>();
        var jobId = NewJobId();
        var ownerId = $"owner-{Guid.NewGuid():N}";

        await repository.CreateAsync(new BackgroundJobModel { JobId = jobId, OwnerId = ownerId, Kind = "Test", Stage = "Running" });

        var running = await repository.FindAsync(jobId, ownerId);
        running.Should().NotBeNull();
        running!.Stage.Should().Be("Running");
        running.ResultJson.Should().BeNull();

        await repository.CompleteAsync(jobId, "Completed", """{"count":3}""");

        var completed = await repository.FindAsync(jobId, ownerId);
        completed!.Stage.Should().Be("Completed");
        completed.ResultJson.Should().Be("""{"count":3}""");
    }

    [Fact]
    public async Task Find_ReturnsNull_ForAnotherOwnersJob_AndForAnUnknownId()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBackgroundJobRepository>();
        var jobId = NewJobId();

        await repository.CreateAsync(new BackgroundJobModel { JobId = jobId, OwnerId = "owner-a", Kind = "Test", Stage = "Running" });

        (await repository.FindAsync(jobId, "owner-b")).Should().BeNull();
        (await repository.FindAsync(Guid.NewGuid(), "owner-a")).Should().BeNull();
    }

    [Fact]
    public async Task Fail_SetsTheErrorMessage()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBackgroundJobRepository>();
        var jobId = NewJobId();
        var ownerId = $"owner-{Guid.NewGuid():N}";

        await repository.CreateAsync(new BackgroundJobModel { JobId = jobId, OwnerId = ownerId, Kind = "Test", Stage = "Running" });
        await repository.FailAsync(jobId, "Failed", "boom");

        var failed = await repository.FindAsync(jobId, ownerId);
        failed!.Stage.Should().Be("Failed");
        failed.ErrorMessage.Should().Be("boom");
    }

    /// <summary>
    /// The job id is stored as the document's <c>_id</c> (a plain string, see <see cref="BackgroundJob"/>),
    /// so it can be registered for cleanup before the job is even created.
    /// </summary>
    private Guid NewJobId()
    {
        var jobId = Guid.NewGuid();
        TrackDocument("background_job", jobId.ToString());
        return jobId;
    }
}
