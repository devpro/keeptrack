using System.Text.Json;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.Jobs;

/// <summary>
/// Tracks a background job's progress, so the client polls for real status rather than waiting on one long request.
/// Shared by every long-running action (TV Time import, reference sync, reference import), typed by the feature's own stage enum and result DTO.
/// Backed by MongoDB (<see cref="IBackgroundJobRepository"/>), since the replica answering a poll is not necessarily the one running the job.
/// This typed wrapper translates enum names and JSON, so the Domain contract stays free of web DTO types.
/// </summary>
public class JobStore<TStage, TResult>(IBackgroundJobRepository repository)
    where TStage : struct, Enum
{
    /// <summary>
    /// The feature this store's jobs belong to, shown on the admin system panel, derived from the stage enum's name ("ImportStage" gives "Import") so no feature registers it.
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
    /// Null when the job does not exist or belongs to another owner, which the repository query enforces, so a caller never sees another user's job.
    /// </summary>
    public async Task<(TStage Stage, TResult? Result, string? ErrorMessage)?> GetStatusAsync(Guid jobId, string ownerId)
    {
        var job = await repository.FindAsync(jobId, ownerId);
        if (job is null) return null;

        var result = job.ResultJson is null ? default : JsonSerializer.Deserialize<TResult>(job.ResultJson);
        return (Enum.Parse<TStage>(job.Stage), result, job.ErrorMessage);
    }
}
