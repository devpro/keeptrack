using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Stage of a running TV Time import, reported so the client shows real progress rather than a bare spinner.
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
/// Returned as soon as an import starts, its progress then polled as <see cref="ImportJobStatusDto"/> at GET /api/import/tv-time/{JobId}.
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
