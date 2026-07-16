using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="BackgroundJobModel"/> - deliberately not <see cref="IDataRepository{TModel}"/>
/// (jobs aren't owner-scoped paged CRUD; they're keyed by job id with owner checked on read), same
/// purpose-built-repository reasoning as the owner-less reference repositories.
/// </summary>
public interface IBackgroundJobRepository
{
    Task CreateAsync(BackgroundJobModel job);

    Task UpdateStageAsync(Guid jobId, string stage);

    Task CompleteAsync(Guid jobId, string stage, string resultJson);

    Task FailAsync(Guid jobId, string stage, string errorMessage);

    /// <summary>
    /// Returns null when the job doesn't exist or wasn't created by this owner - a caller can never
    /// observe another user's job, even by guessing a job id.
    /// </summary>
    Task<BackgroundJobModel?> FindAsync(Guid jobId, string ownerId);

    /// <summary>
    /// The most recent jobs across every owner, newest first - admin diagnostics only, which is why this
    /// is the one read deliberately not owner-scoped (the admin endpoint gates access).
    /// </summary>
    Task<List<BackgroundJobModel>> FindRecentAsync(int limit);
}
