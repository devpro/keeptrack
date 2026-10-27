using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="BackgroundJobModel"/>.
/// Not an <see cref="IDataRepository{TModel}"/>, since jobs are keyed by job id with the owner checked on read, not owner-scoped paged CRUD.
/// </summary>
public interface IBackgroundJobRepository
{
    Task CreateAsync(BackgroundJobModel job);

    Task UpdateStageAsync(Guid jobId, string stage);

    Task CompleteAsync(Guid jobId, string stage, string resultJson);

    Task FailAsync(Guid jobId, string stage, string errorMessage);

    /// <summary>
    /// Null when the job does not exist or belongs to another owner, so a caller never sees another user's job, even by guessing its id.
    /// </summary>
    Task<BackgroundJobModel?> FindAsync(Guid jobId, string ownerId);

    /// <summary>
    /// The most recent jobs of every owner, newest first.
    /// For admin diagnostics only, the one read not scoped to an owner, behind an admin endpoint.
    /// </summary>
    Task<List<BackgroundJobModel>> FindRecentAsync(int limit);
}
