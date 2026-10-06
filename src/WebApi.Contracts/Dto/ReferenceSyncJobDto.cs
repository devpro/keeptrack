using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of a running reference-data sync, reported so the client shows real progress rather than a bare spinner.
/// </summary>
public enum ReferenceSyncStage
{
    SyncingTvShows,
    SyncingMovies,
    SyncingBooks,
    SyncingVideoGames,
    SyncingAlbums,

    /// <summary>
    /// Rebuilding the Explore rankings, the last phase of a full pass and the only one of an Explore-only run.
    /// It has its own stage, since walking several provider pages per ordering can outlast every reference domain together.
    /// </summary>
    RefreshingExplore,
    Completed,
    Failed
}

/// <summary>
/// Returned as soon as a sync starts, its progress then polled as <see cref="ReferenceSyncJobStatusDto"/> at GET /api/reference-data/sync-now/{JobId}.
/// </summary>
public class ReferenceSyncJobDto
{
    public required Guid JobId { get; set; }
}

/// <summary>
/// Current status of a reference-data sync job.
/// </summary>
public class ReferenceSyncJobStatusDto
{
    public required ReferenceSyncStage Stage { get; set; }

    public ReferenceSyncResultDto? Result { get; set; }

    public string? ErrorMessage { get; set; }
}
