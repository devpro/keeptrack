using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The per-type outcome of <see cref="Services.OwnedItemImportCommitCoordinator.CommitAsync"/>, plus the
/// reconciling per-row totals every owned-item importer surfaces so the user can trust nothing was silently
/// dropped: <see cref="RowsImported"/> + the sum of every type's <see cref="TypeCounts.Skipped"/> always
/// equals the number of rows submitted (several rows sharing a title consolidate into one item, which makes
/// the created/merged counts add up to less than the row count without any loss).
/// </summary>
public sealed class OwnedItemImportCommitCounts
{
    public TypeCounts Books { get; } = new();
    public TypeCounts Movies { get; } = new();
    public TypeCounts TvShows { get; } = new();
    public TypeCounts VideoGames { get; } = new();
    public TypeCounts Gear { get; } = new();
    public TypeCounts Collectibles { get; } = new();

    /// <summary>The true per-row count of rows that got an owned copy added, across every type.</summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row skipped as an already-imported duplicate, in submission order.</summary>
    public List<string> SkippedTitles { get; } = [];
}

/// <summary>Created / merged-into / skipped counts for one trackable type within a single commit.</summary>
public sealed class TypeCounts
{
    /// <summary>Brand new items created.</summary>
    public int Created { get; set; }

    /// <summary>Existing (or created-earlier-this-batch) items that received an additional owned copy.</summary>
    public int MergedInto { get; set; }

    /// <summary>Rows whose reference already matched an existing owned copy - not duplicated.</summary>
    public int Skipped { get; set; }
}
