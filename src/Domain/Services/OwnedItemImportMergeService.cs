using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes what to create and update when committing reviewed import rows, for any trackable type.
/// Pure: it takes the owner's items and the selected rows and returns a plan, the caller doing all repository access.
/// Matching is by normalized title (<see cref="TitleNormalizer"/>), also within the batch:
/// two rows sharing a title become one item with two copies, even when neither existed before.
///
/// Generic over the model and its request-item shape through an <see cref="OwnedItemImportAdapter{TModel,TRequestItem}"/> of delegates rather than a shared interface.
/// The <c>OwnedVersions</c> of most types and the differently shaped <c>Platforms</c> of video games thus share one algorithm, with no change to the models.
/// </summary>
public static class OwnedItemImportMergeService
{
    /// <summary>
    /// Every reference recorded on an existing owned copy, so the preview flags rows imported before and a newer export does not duplicate them.
    /// Compared by exact equality with the importer's own reference format (such as <see cref="AmazonImportMergeService.FormatOrderReference"/>),
    /// which gives line-item rather than order precision.
    /// <paramref name="getReferences"/> reads the collection holding <typeparamref name="TModel"/>'s copies (<c>OwnedVersions</c> or <c>Platforms</c>).
    /// </summary>
    public static HashSet<string> FindImportedReferences<TModel>(IEnumerable<TModel> existingItems, Func<TModel, IEnumerable<string?>> getReferences) =>
        existingItems.SelectMany(getReferences).Where(reference => reference is not null).ToHashSet()!;

    /// <summary>
    /// <paramref name="adapter"/>'s <c>GetExistingReferences</c>
    /// and <c>GetItemReference</c> make the importer's reference (see <see cref="FindImportedReferences{TModel}"/>) the primary dedup key, not only a preview flag.
    /// A row whose reference already exists on an item, under any title, even one reference linking renamed, is skipped rather than matched by title.
    /// Title matching alone would add the same copy again on every re-commit, and would create a duplicate item once linking renamed the first one.
    /// Title matching remains the fallback for a new order of an item already owned, a second copy bought separately.
    /// </summary>
    public static ImportCommitPlan<TModel> ComputeCommitPlan<TModel, TRequestItem>(
        IReadOnlyCollection<TModel> existingItems,
        IReadOnlyList<TRequestItem> items,
        OwnedItemImportAdapter<TModel, TRequestItem> adapter)
        where TModel : class
    {
        var plan = new ImportCommitPlan<TModel>();

        var byNormalizedTitle = new Dictionary<string, TModel>();
        var byReference = new Dictionary<string, TModel>();
        IndexExistingItems(existingItems, adapter, byNormalizedTitle, byReference);

        // Items created earlier in this batch are tracked apart from existing ones:
        // a later row matching one only appends its copy, already part of ItemsToCreate, and never queues an update for an item with no id yet.
        var createdThisBatch = new HashSet<TModel>();

        foreach (var item in items)
        {
            MergeItem(item, plan, byNormalizedTitle, byReference, createdThisBatch, adapter);
        }

        return plan;
    }

    private static void IndexExistingItems<TModel, TRequestItem>(
        IReadOnlyCollection<TModel> existingItems,
        OwnedItemImportAdapter<TModel, TRequestItem> adapter,
        Dictionary<string, TModel> byNormalizedTitle,
        Dictionary<string, TModel> byReference)
        where TModel : class
    {
        foreach (var existing in existingItems)
        {
            byNormalizedTitle.TryAdd(TitleNormalizer.Normalize(adapter.GetExistingTitle(existing)), existing);
            foreach (var reference in adapter.GetExistingReferences(existing).OfType<string>())
            {
                byReference.TryAdd(reference, existing);
            }
        }
    }

    private static void MergeItem<TModel, TRequestItem>(
        TRequestItem item,
        ImportCommitPlan<TModel> plan,
        Dictionary<string, TModel> byNormalizedTitle,
        Dictionary<string, TModel> byReference,
        HashSet<TModel> createdThisBatch,
        OwnedItemImportAdapter<TModel, TRequestItem> adapter)
        where TModel : class
    {
        var reference = adapter.GetItemReference(item);
        if (reference is not null && byReference.ContainsKey(reference))
        {
            plan.OwnedCopiesSkipped++;
            plan.SkippedTitles.Add(adapter.GetItemTitle(item));
            return;
        }

        var key = TitleNormalizer.Normalize(adapter.GetItemTitle(item));
        TModel target;

        if (byNormalizedTitle.TryGetValue(key, out var existing))
        {
            adapter.AppendOwnedCopy(existing, item);
            if (!createdThisBatch.Contains(existing) && !plan.ItemsToUpdate.Contains(existing))
            {
                plan.ItemsToUpdate.Add(existing);
            }

            target = existing;
        }
        else
        {
            var created = adapter.CreateNew(item);
            plan.ItemsToCreate.Add(created);
            createdThisBatch.Add(created);

            // so a later row in the same batch sharing this title merges into it too, instead of creating a second item
            byNormalizedTitle[key] = created;
            target = created;
        }

        // registered now, not only from the initial scan, so a later row of the batch carrying the same reference is caught too
        if (reference is not null) byReference[reference] = target;

        plan.OwnedCopiesAdded++;
    }
}
