using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What a reference-data zip import did, per collection: how many documents matched an existing one (updated
/// in place, keeping the target's own <c>_id</c> so every tenant's <c>ReferenceId</c> still resolves) and how
/// many were new. <see cref="SkippedExternalIds"/> is the one thing an admin has to be told about rather than
/// left to discover - see <see cref="Services.ReferenceDataImportService"/>.
/// </summary>
public class ReferenceDataImportSummary
{
    public ReferenceDataImportCounts TvShows { get; } = new();

    public ReferenceDataImportCounts Movies { get; } = new();

    public ReferenceDataImportCounts People { get; } = new();

    public ReferenceDataImportCounts Books { get; } = new();

    public ReferenceDataImportCounts VideoGames { get; } = new();

    public ReferenceDataImportCounts Albums { get; } = new();

    /// <summary>
    /// Every "provider:id" the import could not carry over because a *different* document in the target
    /// database already claims it - the two-documents-for-one-work case (e.g. the target linked a book
    /// through Google Books and the same book separately through Open Library). Writing the id anyway would
    /// hit the unique partial index on <c>external_ids.*</c> and abort the whole import, so the document is
    /// imported without that one key and the collision is reported instead of silently resolved: merging two
    /// existing reference documents is an admin decision, not an import's.
    /// </summary>
    public List<string> SkippedExternalIds { get; } = [];
}

/// <summary>Per-collection outcome of a reference-data import.</summary>
public class ReferenceDataImportCounts
{
    /// <summary>Documents that matched an existing one (by provider id, else by <c>_id</c>) and were merged into it.</summary>
    public int Updated { get; set; }

    /// <summary>Documents the target database had no counterpart for, inserted as new.</summary>
    public int Created { get; set; }

    public int Total => Updated + Created;
}
