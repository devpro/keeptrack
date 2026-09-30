using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes what to create/update when committing a set of user-reviewed import rows, for any trackable item
/// type. Pure: takes the owner's already-fetched items and the selected rows, returns a plan - all
/// repository access stays in the calling controller. Matching is by normalized title
/// (<see cref="TitleNormalizer"/>, the same "same title" rule the TV Time import already established),
/// merging within the same commit batch too: two selected rows sharing a title become one item with two
/// owned copies, even if neither existed before this commit.
///
/// Generic over both the tracked model (<c>BookModel</c>/<c>MovieModel</c>/<c>TvShowModel</c>/<c>VideoGameModel</c>)
/// and its own request-item shape via an <see cref="OwnedItemImportAdapter{TModel,TRequestItem}"/> of delegates
/// rather than a shared interface - Book/Movie/TvShow's <c>OwnedVersions</c> and VideoGame's differently-shaped
/// <c>Platforms</c> both flow through the exact same algorithm this way, with no changes to any of those models.
/// The six delegates are bundled into one adapter value (rather than threaded individually) so the methods below
/// don't each repeat all six as separate parameters. Extracted out of the originally Amazon-only
/// <see cref="AmazonImportMergeService"/> once a second importer (the generic video game transaction import)
/// needed the exact same engine - the two members here were already fully generic (no Amazon-specific
/// concept anywhere in their bodies), only <see cref="AmazonImportMergeService.FormatOrderReference"/> and
/// <see cref="AmazonImportMergeService.BuildAmazonProvenanceNotes"/> are genuinely Amazon-specific and stayed
/// behind.
/// </summary>
public static class OwnedItemImportMergeService
{
    /// <summary>
    /// Every reference already recorded on an existing owned copy - used at preview time to flag rows that
    /// look like they were imported before, so re-uploading a newer export doesn't duplicate them. Compared
    /// by exact string equality against whatever reference-formatting the calling importer uses for its own
    /// candidate rows (e.g. <see cref="AmazonImportMergeService.FormatOrderReference"/>), which is what makes
    /// per-line-item (not per-order) precision actually take effect. <paramref name="getReferences"/> reads
    /// whichever collection carries the owned copies for <typeparamref name="TModel"/> (<c>OwnedVersions</c>
    /// or <c>Platforms</c>).
    /// </summary>
    public static HashSet<string> FindImportedReferences<TModel>(IEnumerable<TModel> existingItems, Func<TModel, IEnumerable<string?>> getReferences) =>
        existingItems.SelectMany(getReferences).Where(reference => reference is not null).ToHashSet()!;

    /// <summary>
    /// <paramref name="adapter"/>'s <c>GetExistingReferences</c>/<c>GetItemReference</c> make the caller's own
    /// reference (see <see cref="FindImportedReferences{TModel}"/>) the *primary* dedup key, not just an
    /// advisory preview-time flag: a re-committed row whose reference already exists on some existing item -
    /// under any title, even one reference-data linking has since renamed - is skipped outright rather than
    /// falling through to title matching. Two real bugs (found on the original Amazon import) motivated this:
    /// (1) re-running the same commit created a second owned copy for the same order every time, because
    /// title-matching alone doesn't know "this exact copy is already here"; (2) once an item's title changed
    /// after a first import, title-matching a re-import of the same order no longer found it at all and
    /// created a brand new duplicate item instead. Title matching is still the fallback for a genuinely new
    /// order of an item already owned under a different order (a second copy bought separately).
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

        // Items created earlier in this same batch are tracked separately from pre-existing ones: a later
        // row matching one must only get its owned copy appended (already reflected via ItemsToCreate),
        // never also queued onto ItemsToUpdate - it has no Id yet, so "updating" it would be meaningless.
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

            // so a later row in the same batch sharing this title merges into it too, instead of
            // creating a second item
            byNormalizedTitle[key] = created;
            target = created;
        }

        // registers this reference immediately (not just from the initial existingItems scan), so a
        // second row in the same batch carrying the same reference is caught by the check above too
        if (reference is not null) byReference[reference] = target;

        plan.OwnedCopiesAdded++;
    }
}
