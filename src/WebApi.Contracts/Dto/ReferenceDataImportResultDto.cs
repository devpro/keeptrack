using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// What a reference-data zip import (POST /api/reference-data/import) did, per collection. Documents are
/// matched by provider id (TMDB, IGDB, Google Books...), never by the <c>_id</c> they were exported with, so
/// "updated" means the target database already knew that work - under its own id, which the import keeps.
/// </summary>
public class ReferenceDataImportResultDto
{
    public required ReferenceDataImportCountsDto TvShows { get; set; }

    public required ReferenceDataImportCountsDto Movies { get; set; }

    public required ReferenceDataImportCountsDto People { get; set; }

    public required ReferenceDataImportCountsDto Books { get; set; }

    public required ReferenceDataImportCountsDto VideoGames { get; set; }

    public required ReferenceDataImportCountsDto Albums { get; set; }

    /// <summary>
    /// Provider ids ("provider:id") the import could not carry over because a different document in the target
    /// database already claims them - two reference documents for one work, which only an admin can merge.
    /// Empty on a normal import; anything listed here is worth acting on, not a routine warning.
    /// </summary>
    public required List<string> SkippedExternalIds { get; set; }
}

/// <summary>One collection's import outcome.</summary>
public class ReferenceDataImportCountsDto
{
    /// <summary>Documents that matched one the target already had, and were merged into it.</summary>
    public required int Updated { get; set; }

    /// <summary>Documents the target had no counterpart for, inserted as new.</summary>
    public required int Created { get; set; }
}
