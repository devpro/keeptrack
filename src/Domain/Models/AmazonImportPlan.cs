using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What <see cref="Services.AmazonImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> decided:
/// brand new items to create, and existing (or already-created-this-batch) items to update - each already
/// carrying the extra owned copy appended (an <see cref="OwnedVersionModel"/> or a
/// <see cref="VideoGamePlatformModel"/>, depending on <typeparamref name="TModel"/>).
/// </summary>
public class AmazonImportPlan<TModel>
{
    public List<TModel> ItemsToCreate { get; set; } = [];

    public List<TModel> ItemsToUpdate { get; set; } = [];

    public int OwnedCopiesAdded { get; set; }

    /// <summary>A row whose order reference already matched an existing owned copy - not duplicated.</summary>
    public int OwnedCopiesSkipped { get; set; }
}
