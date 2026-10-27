using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> decided:
/// new items to create, and existing items (or ones created earlier in this batch) to update.
/// Each already carries its appended owned copy, an <see cref="OwnedVersionModel"/> or a <see cref="VideoGamePlatformModel"/> depending on <typeparamref name="TModel"/>.
/// </summary>
public class ImportCommitPlan<TModel>
{
    public List<TModel> ItemsToCreate { get; set; } = [];

    public List<TModel> ItemsToUpdate { get; set; } = [];

    /// <summary>
    /// Every row that got an owned copy added: the per-row count, where <see cref="ItemsToCreate"/> and <see cref="ItemsToUpdate"/> count distinct items.
    /// Selected rows sharing a title consolidate into one new item, each row still getting its copy, so the item counts can be lower than the selected rows.
    /// <c>OwnedCopiesAdded + OwnedCopiesSkipped</c> always equals the rows submitted, a total that shows the user nothing was silently dropped.
    /// </summary>
    public int OwnedCopiesAdded { get; set; }

    /// <summary>Rows whose reference already matched an existing owned copy, so they are not duplicated.</summary>
    public int OwnedCopiesSkipped { get; set; }

    /// <summary>The title of each row counted in <see cref="OwnedCopiesSkipped"/>, in submission order, so the user sees which rows were treated as duplicates.</summary>
    public List<string> SkippedTitles { get; set; } = [];
}
