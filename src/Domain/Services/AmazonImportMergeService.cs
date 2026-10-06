using System.Collections.Generic;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The Amazon-specific formatting of a commit: the ASIN-based reference text and the provenance notes.
/// The create, merge and dedup engine is generic and lives in <see cref="OwnedItemImportMergeService"/>.
/// </summary>
public static class AmazonImportMergeService
{
    /// <summary>
    /// Formats an imported order line's owned copy <c>Reference</c>, which is human-readable and also the exact dedup key <see cref="OwnedItemImportMergeService.FindImportedReferences{TModel}"/> looks for on a re-import.
    /// It includes the ASIN, not only the order id, since one order often holds several items.
    /// With the order id alone, a second item of the same order would be skipped as a duplicate of the first, and flagged "already imported" in the preview.
    /// The ASIN is Amazon's stable product id, unlike the title, which the user can edit before commit.
    /// </summary>
    public static string FormatOrderReference(string orderId, string asin) => $"Amazon order {orderId} (ASIN {asin})";

    /// <summary>
    /// Keeps Amazon's original listing text on an item this import creates.
    /// Reference linking may overwrite the title (and a book's ISBN), and the user may have edited the title before commit.
    /// Only used on creation, since an existing item's provenance is not this import's to invent.
    /// <paramref name="isbn"/> is null for every domain but books.
    /// </summary>
    public static string BuildAmazonProvenanceNotes(string amazonTitle, string? isbn)
    {
        var lines = new List<string> { $"Title from Amazon: {amazonTitle}" };
        if (isbn is not null) lines.Add($"ISBN from Amazon: {isbn}");
        return string.Join('\n', lines);
    }
}
