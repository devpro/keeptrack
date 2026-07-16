using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Jobs;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Jobs;

/// <summary>
/// Covers <see cref="JobStore{TStage,TResult}"/>'s own responsibility - the typed enum-name/JSON
/// translation over the string-based <see cref="IBackgroundJobRepository"/> contract - against an
/// in-memory fake repository. The real MongoDB persistence (including the owner-scoping query) is
/// covered by <c>BackgroundJobRepositoryTest</c> in the integration suite; the fake below mirrors the
/// same owner-check contract so the wrapper's null passthrough is still exercised here.
/// </summary>
[Trait("Category", "UnitTests")]
public class JobStoreTest
{
    private enum TestStage
    {
        Running,
        Completed,
        Failed
    }

    private sealed record TestResult(string Message, int Count);

    private sealed class InMemoryBackgroundJobRepository : IBackgroundJobRepository
    {
        private readonly Dictionary<Guid, BackgroundJobModel> _jobs = [];

        public Task CreateAsync(BackgroundJobModel job)
        {
            _jobs[job.JobId] = job;
            return Task.CompletedTask;
        }

        public Task UpdateStageAsync(Guid jobId, string stage)
        {
            if (_jobs.TryGetValue(jobId, out var job)) job.Stage = stage;
            return Task.CompletedTask;
        }

        public Task CompleteAsync(Guid jobId, string stage, string resultJson)
        {
            if (_jobs.TryGetValue(jobId, out var job))
            {
                job.Stage = stage;
                job.ResultJson = resultJson;
            }

            return Task.CompletedTask;
        }

        public Task FailAsync(Guid jobId, string stage, string errorMessage)
        {
            if (_jobs.TryGetValue(jobId, out var job))
            {
                job.Stage = stage;
                job.ErrorMessage = errorMessage;
            }

            return Task.CompletedTask;
        }

        public Task<BackgroundJobModel?> FindAsync(Guid jobId, string ownerId) =>
            Task.FromResult(_jobs.TryGetValue(jobId, out var job) && job.OwnerId == ownerId ? job : null);

        public Task<List<BackgroundJobModel>> FindRecentAsync(int limit) =>
            Task.FromResult(new List<BackgroundJobModel>(_jobs.Values));

        public BackgroundJobModel this[Guid jobId] => _jobs[jobId];
    }

    [Fact]
    public async Task Create_ThenGetStatus_ReflectsTheInitialStage()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());

        var jobId = await store.CreateAsync("owner-1", TestStage.Running);
        var status = await store.GetStatusAsync(jobId, "owner-1");

        status.Should().NotBeNull();
        status!.Value.Stage.Should().Be(TestStage.Running);
        status.Value.Result.Should().BeNull();
        status.Value.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public async Task UpdateStage_IsReflectedOnTheNextGetStatus()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());
        var jobId = await store.CreateAsync("owner-1", TestStage.Running);

        await store.UpdateStageAsync(jobId, TestStage.Completed);

        (await store.GetStatusAsync(jobId, "owner-1"))!.Value.Stage.Should().Be(TestStage.Completed);
    }

    [Fact]
    public async Task Complete_RoundTripsTheResultThroughItsJsonPayload()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());
        var jobId = await store.CreateAsync("owner-1", TestStage.Running);

        await store.CompleteAsync(jobId, TestStage.Completed, new TestResult("all done", 42));

        var status = await store.GetStatusAsync(jobId, "owner-1");
        status!.Value.Stage.Should().Be(TestStage.Completed);
        status.Value.Result.Should().Be(new TestResult("all done", 42));
    }

    [Fact]
    public async Task Fail_SetsTheTerminalStageAndErrorMessage()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());
        var jobId = await store.CreateAsync("owner-1", TestStage.Running);

        await store.FailAsync(jobId, TestStage.Failed, "boom");

        var status = await store.GetStatusAsync(jobId, "owner-1");
        status!.Value.Stage.Should().Be(TestStage.Failed);
        status.Value.ErrorMessage.Should().Be("boom");
    }

    [Fact]
    public async Task Create_DerivesTheJobKind_FromTheStageEnumName()
    {
        var repository = new InMemoryBackgroundJobRepository();
        var store = new JobStore<TestStage, TestResult>(repository);

        var jobId = await store.CreateAsync("owner-1", TestStage.Running);

        // "TestStage" minus the "Stage" suffix - the same rule that yields "Import"/"ReferenceSync"
        repository[jobId].Kind.Should().Be("Test");
    }

    [Fact]
    public async Task GetStatus_ReturnsNull_ForAnUnknownJobId()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());

        (await store.GetStatusAsync(Guid.NewGuid(), "owner-1")).Should().BeNull();
    }

    [Fact]
    public async Task GetStatus_ReturnsNull_ForAJobBelongingToADifferentOwner()
    {
        var store = new JobStore<TestStage, TestResult>(new InMemoryBackgroundJobRepository());
        var jobId = await store.CreateAsync("owner-1", TestStage.Running);

        (await store.GetStatusAsync(jobId, "owner-2")).Should().BeNull();
    }
}
