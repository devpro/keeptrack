using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes what to create/update when committing a set of user-reviewed Amazon order rows, for any
/// trackable item type. Pure: takes the owner's already-fetched items and the selected rows, returns a plan -
/// all repository access stays in <c>AmazonImportController</c>. Matching is by normalized title
/// (<see cref="TitleNormalizer"/>, the same "same title" rule the TV Time import already established),
/// merging within the same commit batch too: two selected rows sharing a title become one item with two
/// owned copies, even if neither existed before this commit.
///
/// Generic over both the tracked model (<c>BookModel</c>/<c>MovieModel</c>/<c>TvShowModel</c>/<c>VideoGameModel</c>)
/// and its own request-item shape (<c>AmazonOwnedItemImportRequestItem</c> for the first three,
/// <c>AmazonVideoGameImportRequestItem</c> for VideoGame) via delegates rather than a shared interface -
/// Book/Movie/TvShow's <c>OwnedVersions</c> and VideoGame's differently-shaped <c>Platforms</c> both flow
/// through the exact same algorithm this way, with no changes to any of those models.
/// </summary>
public static class AmazonImportMergeService
{
    /// <summary>
    /// The one place that formats an owned copy's <c>Reference</c> for an imported order line - human-readable,
    /// and also the exact-match dedup key <see cref="FindImportedReferences{TModel}"/> looks for on a later
    /// re-import. Includes the ASIN, not just the order id: a single Amazon order commonly contains several
    /// different line items, and order-id-only matching (a real bug, found before this shipped) meant a
    /// second, genuinely different item from the same order was silently skipped as a "duplicate" of the
    /// first - or, at preview time, incorrectly flagged "already imported" just because a sibling item from
    /// the same order had been. The ASIN is Amazon's own stable per-product id, already parsed from every
    /// row, so it's a precise disambiguator - unlike the product title, which is user-editable before commit.
    /// </summary>
    public static string FormatOrderReference(string orderId, string asin) => $"Amazon order {orderId} (ASIN {asin})";

    /// <summary>
    /// Every reference already recorded on an existing owned copy - used at preview time to flag rows that
    /// look like they were imported before, so re-uploading a newer export doesn't duplicate them. Compared
    /// by exact string equality against <see cref="FormatOrderReference"/> computed for a candidate row,
    /// which is what makes the per-line-item (not per-order) precision above actually take effect.
    /// <paramref name="getReferences"/> reads whichever collection carries the owned copies for
    /// <typeparamref name="TModel"/> (<c>OwnedVersions</c> or <c>Platforms</c>).
    /// </summary>
    public static HashSet<string> FindImportedReferences<TModel>(IEnumerable<TModel> existingItems, Func<TModel, IEnumerable<string?>> getReferences) =>
        existingItems.SelectMany(getReferences).Where(reference => reference is not null).ToHashSet()!;

    /// <summary>
    /// <paramref name="getExistingReferences"/>/<paramref name="getItemReference"/> make the order
    /// reference (see <see cref="FormatOrderReference"/>) the *primary* dedup key, not just an advisory
    /// preview-time flag: a re-committed row whose reference already exists on some existing item - under
    /// any title, even one reference-data linking has since renamed - is skipped outright rather than
    /// falling through to title matching. Two real bugs motivated this: (1) re-running the same commit
    /// created a second owned copy for the same order every time, because title-matching alone doesn't
    /// know "this exact copy is already here"; (2) once an item's title changed after a first import,
    /// title-matching a re-import of the same order no longer found it at all and created a brand new
    /// duplicate item instead. Title matching is still the fallback for a genuinely new order of an item
    /// already owned under a different order (a second copy bought separately).
    /// </summary>
    public static AmazonImportPlan<TModel> ComputeCommitPlan<TModel, TRequestItem>(
        IReadOnlyCollection<TModel> existingItems,
        IReadOnlyList<TRequestItem> items,
        Func<TModel, string> getExistingTitle,
        Func<TModel, IEnumerable<string?>> getExistingReferences,
        Func<TRequestItem, string> getItemTitle,
        Func<TRequestItem, string?> getItemReference,
        Func<TRequestItem, TModel> createNew,
        Action<TModel, TRequestItem> appendOwnedCopy)
        where TModel : class
    {
        var plan = new AmazonImportPlan<TModel>();

        var byNormalizedTitle = new Dictionary<string, TModel>();
        var byReference = new Dictionary<string, TModel>();
        foreach (var existing in existingItems)
        {
            byNormalizedTitle.TryAdd(TitleNormalizer.Normalize(getExistingTitle(existing)), existing);
            foreach (var reference in getExistingReferences(existing))
            {
                if (reference is not null) byReference.TryAdd(reference, existing);
            }
        }

        // Items created earlier in this same batch are tracked separately from pre-existing ones: a later
        // row matching one must only get its owned copy appended (already reflected via ItemsToCreate),
        // never also queued onto ItemsToUpdate - it has no Id yet, so "updating" it would be meaningless.
        var createdThisBatch = new HashSet<TModel>();

        foreach (var item in items)
        {
            var reference = getItemReference(item);
            if (reference is not null && byReference.ContainsKey(reference))
            {
                plan.OwnedCopiesSkipped++;
                continue;
            }

            var key = TitleNormalizer.Normalize(getItemTitle(item));
            TModel target;

            if (byNormalizedTitle.TryGetValue(key, out var existing))
            {
                appendOwnedCopy(existing, item);
                if (!createdThisBatch.Contains(existing) && !plan.ItemsToUpdate.Contains(existing))
                {
                    plan.ItemsToUpdate.Add(existing);
                }

                target = existing;
            }
            else
            {
                var created = createNew(item);
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

        return plan;
    }

    /// <summary>
    /// Reference-data linking is expected to overwrite the created item's title (and, for a book, its ISBN)
    /// with the provider's canonical values, and the user may have already cleaned up the title before
    /// commit - so this is the one place Amazon's own original listing text is preserved, for an item
    /// created by this import. Only used at creation time: a pre-existing item's provenance isn't this
    /// import's to invent. <paramref name="isbn"/> is null for every domain but Book.
    /// </summary>
    public static string BuildAmazonProvenanceNotes(string amazonTitle, string? isbn)
    {
        var lines = new List<string> { $"Title from Amazon: {amazonTitle}" };
        if (isbn is not null) lines.Add($"ISBN from Amazon: {isbn}");
        return string.Join('\n', lines);
    }
}
