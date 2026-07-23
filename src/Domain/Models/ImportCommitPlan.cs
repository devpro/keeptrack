using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> decided:
/// brand new items to create, and existing (or already-created-this-batch) items to update - each already
/// carrying the extra owned copy appended (an <see cref="OwnedVersionModel"/> or a
/// <see cref="VideoGamePlatformModel"/>, depending on <typeparamref name="TModel"/>).
/// </summary>
public class ImportCommitPlan<TModel>
{
    public List<TModel> ItemsToCreate { get; set; } = [];

    public List<TModel> ItemsToUpdate { get; set; } = [];

    /// <summary>
    /// Every row that successfully got an owned copy added - the true per-row count, unlike
    /// <see cref="ItemsToCreate"/>/<see cref="ItemsToUpdate"/>'s counts, which are per distinct item.
    /// Several selected rows sharing a title can consolidate into a single newly-created item within one
    /// commit batch, which is not a data loss (every one of those rows still got its owned copy), but does
    /// make <c>ItemsToCreate.Count + ItemsToUpdate.Count</c> come out lower than the number of selected rows.
    /// <c>OwnedCopiesAdded + OwnedCopiesSkipped</c> always equals the number of rows submitted - the
    /// reconciling total a caller can show the user to prove nothing was silently dropped.
    /// </summary>
    public int OwnedCopiesAdded { get; set; }

    /// <summary>A row whose reference already matched an existing owned copy - not duplicated.</summary>
    public int OwnedCopiesSkipped { get; set; }

    /// <summary>The title of each row counted in <see cref="OwnedCopiesSkipped"/>, in submission order - lets a
    /// caller show the user exactly which selected rows were treated as already-imported duplicates.</summary>
    public List<string> SkippedTitles { get; set; } = [];
}
