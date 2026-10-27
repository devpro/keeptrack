using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// What a reference-data zip import (POST /api/reference-data/import) did, per collection.
/// Documents match by provider id (TMDB, IGDB, Google Books), never by their exported <c>_id</c>,
/// so "updated" means the target already knew the work under its own id, which the import keeps.
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
    /// Provider ids ("provider:id") the import could not carry over because another document of the target claims them: two documents for one work, which only an admin can merge.
    /// Empty on a normal import, so anything listed is worth acting on.
    /// </summary>
    public required List<string> SkippedExternalIds { get; set; }

    /// <summary>
    /// Works the import created a new document for although the target held one under another provider's id, as <c>"collection:Title (Year)"</c>.
    /// Nothing was lost, but each is two documents for one work, which the provider reconciliation screen can merge.
    /// See <c>ReferenceDataImportSummary.PossibleDuplicates</c> for why the import does not merge them itself.
    /// </summary>
    public List<string> PossibleDuplicates { get; set; } = [];
}

/// <summary>One collection's import outcome.</summary>
public class ReferenceDataImportCountsDto
{
    /// <summary>Documents that matched one the target already had, and were merged into it.</summary>
    public required int Updated { get; set; }

    /// <summary>Documents the target had no counterpart for, inserted as new.</summary>
    public required int Created { get; set; }
}
