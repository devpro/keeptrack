using System.Text.Json;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.Jobs;

/// <summary>
/// Tracks the progress of a background job so the client can poll for real status instead of waiting on
/// a single opaque request - shared by every feature with a long-running admin/user-triggered action
/// (TV Time import, reference-data "sync now"), parameterized by that feature's own stage enum and result
/// DTO rather than duplicated per feature. Backed by MongoDB (<see cref="IBackgroundJobRepository"/>),
/// not memory: with multiple WebApi replicas, the replica answering a poll is not necessarily the one
/// running the job, and the old in-memory store made polling fail whenever they differed. This typed
/// wrapper owns the enum-name/JSON translation so the Domain contract stays free of web DTO types.
/// </summary>
public class JobStore<TStage, TResult>(IBackgroundJobRepository repository)
    where TStage : struct, Enum
{
    /// <summary>
    /// The feature this store's jobs belong to, shown on the admin system-status panel - derived from the
    /// stage enum's name ("ImportStage" -> "Import"), the one piece of identity every closed generic
    /// already carries without per-feature registration ceremony.
    /// </summary>
    private static readonly string Kind = typeof(TStage).Name.EndsWith("Stage", StringComparison.Ordinal)
        ? typeof(TStage).Name[..^"Stage".Length]
        : typeof(TStage).Name;

    public async Task<Guid> CreateAsync(string ownerId, TStage initialStage)
    {
        var jobId = Guid.NewGuid();
        await repository.CreateAsync(new BackgroundJobModel { JobId = jobId, OwnerId = ownerId, Kind = Kind, Stage = initialStage.ToString() });
        return jobId;
    }

    public async Task UpdateStageAsync(Guid jobId, TStage stage) =>
        await repository.UpdateStageAsync(jobId, stage.ToString());

    public async Task CompleteAsync(Guid jobId, TStage completedStage, TResult result) =>
        await repository.CompleteAsync(jobId, completedStage.ToString(), JsonSerializer.Serialize(result));

    public async Task FailAsync(Guid jobId, TStage failedStage, string errorMessage) =>
        await repository.FailAsync(jobId, failedStage.ToString(), errorMessage);

    /// <summary>
    /// Returns null if the job doesn't exist or wasn't created by this owner - a caller can never observe
    /// another user's job, even by guessing a job id (enforced by the repository query itself).
    /// </summary>
    public async Task<(TStage Stage, TResult? Result, string? ErrorMessage)?> GetStatusAsync(Guid jobId, string ownerId)
    {
        var job = await repository.FindAsync(jobId, ownerId);
        if (job is null) return null;

        var result = job.ResultJson is null ? default : JsonSerializer.Deserialize<TResult>(job.ResultJson);
        return (Enum.Parse<TStage>(job.Stage), result, job.ErrorMessage);
    }
}
