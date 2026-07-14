using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of an in-progress reference-data sync, reported back to the client so it can show real progress
/// instead of a single opaque "syncing..." spinner.
/// </summary>
public enum ReferenceSyncStage
{
    SyncingTvShows,
    SyncingMovies,
    SyncingBooks,
    SyncingVideoGames,
    SyncingAlbums,
    Completed,
    Failed
}

/// <summary>
/// Returned immediately when a sync is started; poll <see cref="ReferenceSyncJobStatusDto"/> at
/// GET /api/reference-data/sync-now/{JobId} for progress.
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
