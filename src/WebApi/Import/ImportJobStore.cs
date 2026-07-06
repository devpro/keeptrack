using System;
using System.Collections.Concurrent;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Tracks the progress of background import jobs so the client can poll for real status instead of
/// waiting on a single opaque request. In-memory only - fine for a personal, occasional import feature,
/// and means jobs don't survive an app restart, which is an acceptable trade-off here.
/// </summary>
public class ImportJobStore
{
    private readonly ConcurrentDictionary<Guid, Job> _jobs = new();

    public Guid Create(string ownerId)
    {
        var jobId = Guid.NewGuid();
        _jobs[jobId] = new Job(ownerId);
        return jobId;
    }

    public void UpdateStage(Guid jobId, ImportStage stage)
    {
        if (_jobs.TryGetValue(jobId, out var job)) job.Stage = stage;
    }

    public void Complete(Guid jobId, ImportResultDto result)
    {
        if (!_jobs.TryGetValue(jobId, out var job)) return;
        job.Stage = ImportStage.Completed;
        job.Result = result;
    }

    public void Fail(Guid jobId, string errorMessage)
    {
        if (!_jobs.TryGetValue(jobId, out var job)) return;
        job.Stage = ImportStage.Failed;
        job.ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Returns null if the job doesn't exist or wasn't created by this owner - a caller can never
    /// observe another user's import job, even by guessing a job id.
    /// </summary>
    public ImportJobStatusDto? GetStatus(Guid jobId, string ownerId)
    {
        if (!_jobs.TryGetValue(jobId, out var job) || job.OwnerId != ownerId) return null;

        return new ImportJobStatusDto
        {
            Stage = job.Stage,
            Result = job.Result,
            ErrorMessage = job.ErrorMessage
        };
    }

    private sealed class Job(string ownerId)
    {
        public string OwnerId { get; } = ownerId;

        public ImportStage Stage { get; set; } = ImportStage.Parsing;

        public ImportResultDto? Result { get; set; }

        public string? ErrorMessage { get; set; }
    }
}
