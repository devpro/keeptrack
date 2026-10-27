using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of a running reference-data import, reported so the client shows real progress rather than a bare spinner.
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
/// Returned as soon as an import starts, its progress then polled as <see cref="ReferenceDataImportJobStatusDto"/> at GET /api/reference-data/import/{JobId}.
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
