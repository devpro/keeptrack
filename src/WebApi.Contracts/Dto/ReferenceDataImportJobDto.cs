using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of an in-progress reference-data import, reported back to the client so it can show real progress
/// instead of a single opaque "importing..." spinner.
/// </summary>
public enum ReferenceDataImportStage
{
    Parsing,
    ImportingPeople,
    ImportingTvShows,
    ImportingMovies,
    ImportingBooks,
    ImportingVideoGames,
    ImportingAlbums,
    Completed,
    Failed
}

/// <summary>
/// Returned immediately when an import is started; poll <see cref="ReferenceDataImportJobStatusDto"/> at
/// GET /api/reference-data/import/{JobId} for progress.
/// </summary>
public class ReferenceDataImportJobDto
{
    public required Guid JobId { get; set; }
}

/// <summary>
/// Current status of a reference-data import job.
/// </summary>
public class ReferenceDataImportJobStatusDto
{
    public required ReferenceDataImportStage Stage { get; set; }

    public ReferenceDataImportResultDto? Result { get; set; }

    public string? ErrorMessage { get; set; }
}
