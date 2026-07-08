using System;
using System.Collections.Concurrent;

namespace Keeptrack.WebApi.Jobs;

/// <summary>
/// Tracks the progress of a background job so the client can poll for real status instead of waiting on
/// a single opaque request - shared by every feature with a long-running admin/user-triggered action
/// (TV Time import, reference-data "sync now"), parameterized by that feature's own stage enum and result
/// DTO rather than duplicated per feature. In-memory only - fine for occasional, personal-scale actions;
/// jobs don't survive an app restart, an acceptable trade-off here.
/// </summary>
public class JobStore<TStage, TResult>
{
    private readonly ConcurrentDictionary<Guid, Job> _jobs = new();

    public Guid Create(string ownerId, TStage initialStage)
    {
        var jobId = Guid.NewGuid();
        _jobs[jobId] = new Job(ownerId, initialStage);
        return jobId;
    }

    public void UpdateStage(Guid jobId, TStage stage)
    {
        if (_jobs.TryGetValue(jobId, out var job)) job.Stage = stage;
    }

    public void Complete(Guid jobId, TStage completedStage, TResult result)
    {
        if (!_jobs.TryGetValue(jobId, out var job)) return;
        job.Stage = completedStage;
        job.Result = result;
    }

    public void Fail(Guid jobId, TStage failedStage, string errorMessage)
    {
        if (!_jobs.TryGetValue(jobId, out var job)) return;
        job.Stage = failedStage;
        job.ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Returns null if the job doesn't exist or wasn't created by this owner - a caller can never observe
    /// another user's job, even by guessing a job id.
    /// </summary>
    public (TStage Stage, TResult? Result, string? ErrorMessage)? GetStatus(Guid jobId, string ownerId)
    {
        if (!_jobs.TryGetValue(jobId, out var job) || job.OwnerId != ownerId) return null;

        return (job.Stage, job.Result, job.ErrorMessage);
    }

    private sealed class Job(string ownerId, TStage stage)
    {
        public string OwnerId { get; } = ownerId;

        public TStage Stage { get; set; } = stage;

        public TResult? Result { get; set; }

        public string? ErrorMessage { get; set; }
    }
}
