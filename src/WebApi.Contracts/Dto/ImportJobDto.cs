using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of an in-progress TV Time import, reported back to the client so it can show real progress
/// instead of a single opaque "importing..." spinner.
/// </summary>
public enum ImportStage
{
    Parsing,
    ImportingShows,
    ImportingEpisodes,
    ImportingMovies,
    Completed,
    Failed
}

/// <summary>
/// Returned immediately when an import is started; poll <see cref="ImportJobStatusDto"/> at
/// GET /api/import/tv-time/{JobId} for progress.
/// </summary>
public class ImportJobDto
{
    public required Guid JobId { get; set; }
}

/// <summary>
/// Current status of an import job.
/// </summary>
public class ImportJobStatusDto
{
    public required ImportStage Stage { get; set; }

    public ImportResultDto? Result { get; set; }

    public string? ErrorMessage { get; set; }
}
