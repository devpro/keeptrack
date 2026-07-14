using System;
using AwesomeAssertions;
using Keeptrack.WebApi.Jobs;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Jobs;

/// <summary>
/// Covers <see cref="JobStore{TStage,TResult}"/> directly - the shared job-tracking logic behind both TV
/// Time import and reference-data "sync now", generalized out of the old TV-Time-only <c>ImportJobStore</c>
/// so the two features share one implementation instead of duplicating the same create/update/complete/
/// fail/owner-scoping logic.
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

    [Fact]
    public void Create_ThenGetStatus_ReflectsTheInitialStage()
    {
        var store = new JobStore<TestStage, string>();

        var jobId = store.Create("owner-1", TestStage.Running);
        var status = store.GetStatus(jobId, "owner-1");

        status.Should().NotBeNull();
        status!.Value.Stage.Should().Be(TestStage.Running);
        status.Value.Result.Should().BeNull();
        status.Value.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public void UpdateStage_IsReflectedOnTheNextGetStatus()
    {
        var store = new JobStore<TestStage, string>();
        var jobId = store.Create("owner-1", TestStage.Running);

        store.UpdateStage(jobId, TestStage.Completed);

        store.GetStatus(jobId, "owner-1")!.Value.Stage.Should().Be(TestStage.Completed);
    }

    [Fact]
    public void Complete_SetsTheTerminalStageAndResult()
    {
        var store = new JobStore<TestStage, string>();
        var jobId = store.Create("owner-1", TestStage.Running);

        store.Complete(jobId, TestStage.Completed, "all done");

        var status = store.GetStatus(jobId, "owner-1");
        status!.Value.Stage.Should().Be(TestStage.Completed);
        status.Value.Result.Should().Be("all done");
    }

    [Fact]
    public void Fail_SetsTheTerminalStageAndErrorMessage()
    {
        var store = new JobStore<TestStage, string>();
        var jobId = store.Create("owner-1", TestStage.Running);

        store.Fail(jobId, TestStage.Failed, "boom");

        var status = store.GetStatus(jobId, "owner-1");
        status!.Value.Stage.Should().Be(TestStage.Failed);
        status.Value.ErrorMessage.Should().Be("boom");
    }

    [Fact]
    public void GetStatus_ReturnsNull_ForAnUnknownJobId()
    {
        var store = new JobStore<TestStage, string>();

        store.GetStatus(Guid.NewGuid(), "owner-1").Should().BeNull();
    }

    [Fact]
    public void GetStatus_ReturnsNull_ForAJobBelongingToADifferentOwner()
    {
        var store = new JobStore<TestStage, string>();
        var jobId = store.Create("owner-1", TestStage.Running);

        store.GetStatus(jobId, "owner-2").Should().BeNull();
    }
}
