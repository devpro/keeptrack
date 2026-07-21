using System.Collections.Generic;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Amazon-specific formatting used when committing a set of user-reviewed Amazon order rows: the ASIN-based
/// reference text and the provenance-notes text. The actual create/merge/dedup engine used to live here too,
/// but it was already fully generic - it moved to <see cref="OwnedItemImportMergeService"/> once the generic
/// video game transaction importer needed the exact same engine, leaving this class with only the two
/// members that are genuinely Amazon-specific.
/// </summary>
public static class AmazonImportMergeService
{
    /// <summary>
    /// The one place that formats an owned copy's <c>Reference</c> for an imported order line - human-readable,
    /// and also the exact-match dedup key <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/>
    /// looks for on a later re-import. Includes the ASIN, not just the order id: a single Amazon order commonly
    /// contains several different line items, and order-id-only matching (a real bug, found before this shipped)
    /// meant a second, genuinely different item from the same order was silently skipped as a "duplicate" of the
    /// first - or, at preview time, incorrectly flagged "already imported" just because a sibling item from
    /// the same order had been. The ASIN is Amazon's own stable per-product id, already parsed from every
    /// row, so it's a precise disambiguator - unlike the product title, which is user-editable before commit.
    /// </summary>
    public static string FormatOrderReference(string orderId, string asin) => $"Amazon order {orderId} (ASIN {asin})";

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
