namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Counts of documents upserted by a reference-data zip import (POST /api/reference-data/import).
/// </summary>
public class ReferenceDataImportResultDto
{
    public required int TvShowCount { get; set; }

    public required int MovieCount { get; set; }

    public required int PersonCount { get; set; }

    public required int BookCount { get; set; }

    public required int VideoGameCount { get; set; }

    public required int AlbumCount { get; set; }
}
