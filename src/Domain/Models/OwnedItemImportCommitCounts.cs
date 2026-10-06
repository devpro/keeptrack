using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The per-type outcome of <see cref="Services.OwnedItemImportCommitCoordinator.CommitAsync"/>, plus per-row totals showing the user nothing was silently dropped.
/// <see cref="RowsImported"/> plus every type's <see cref="TypeCounts.Skipped"/> always equals the rows submitted.
/// Rows sharing a title consolidate into one item, so the created and merged counts can add up to less than the rows without any loss.
/// </summary>
public sealed class OwnedItemImportCommitCounts
{
    public TypeCounts Books { get; } = new();
    public TypeCounts Movies { get; } = new();
    public TypeCounts TvShows { get; } = new();
    public TypeCounts VideoGames { get; } = new();
    public TypeCounts Gear { get; } = new();
    public TypeCounts Collectibles { get; } = new();

    /// <summary>The rows that got an owned copy added, across every type.</summary>
    public int RowsImported { get; set; }

    /// <summary>The title of each row skipped as an already-imported duplicate, in submission order.</summary>
    public List<string> SkippedTitles { get; } = [];
}

/// <summary>Created, merged-into and skipped counts for one trackable type within a single commit.</summary>
public sealed class TypeCounts
{
    public int Created { get; set; }

    /// <summary>Existing items, or ones created earlier in the batch, that received another owned copy.</summary>
    public int MergedInto { get; set; }

    /// <summary>Rows whose reference already matched an existing owned copy, so they are not duplicated.</summary>
    public int Skipped { get; set; }
}
