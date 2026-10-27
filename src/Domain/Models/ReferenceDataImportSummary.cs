using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What a reference-data import did, per collection: how many documents matched an existing one and how many were new.
/// A match is updated in place under the target's own <c>_id</c>, so every tenant's <c>ReferenceId</c> still resolves.
/// <see cref="SkippedExternalIds"/> is what an admin must be told about (see <see cref="Services.ReferenceDataImportService"/>).
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
    /// Every "provider:id" the import could not carry over because another document in the target already claims it.
    /// That is one work held by two documents, such as a book linked once through Google Books and once through Open Library.
    /// Writing the id would hit the unique index on <c>external_ids.*</c> and abort the import, so the document is imported without that key and the collision reported.
    /// Merging two existing reference documents is an admin's decision, not an import's.
    /// </summary>
    public List<string> SkippedExternalIds { get; } = [];

    /// <summary>
    /// Documents the import created that look, by title and year, like a work the target already had under another provider's id, as <c>"collection:Title (Year)"</c>.
    /// <para>
    /// Matching by provider id cannot close this gap.
    /// An export whose video games are IGDB-linked lands beside the target's RAWG-linked copies of the same games, leaving two documents for one work.
    /// Tenant items point at whichever existed when they linked, so ids, ratings and cover split across the two, and Explore recognises only one.
    /// </para>
    /// <para>
    /// Reported rather than merged, since title text is not identity: two different works do share a title and a year, and fusing them could not be undone.
    /// The admin reconciliation screen shows the same pairs with a merge action, where a human decides.
    /// </para>
    /// </summary>
    public List<string> PossibleDuplicates { get; } = [];
}

/// <summary>Per-collection outcome of a reference-data import.</summary>
public class ReferenceDataImportCounts
{
    /// <summary>Documents that matched an existing one, by provider id or else by <c>_id</c>, and were merged into it.</summary>
    public int Updated { get; set; }

    /// <summary>Documents the target database had no counterpart for, inserted as new.</summary>
    public int Created { get; set; }

    public int Total => Updated + Created;
}
