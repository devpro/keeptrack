using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The identity of a trackable item for "do I already have this?" matching, independent of its concrete
/// model type. <see cref="Creator"/> is the book author / album artist and null for the other media types.
/// </summary>
public sealed record ItemMatchKey(string? ReferenceId, string Title, int? Year, string? Creator);

/// <summary>
/// Decides whether two items are "the same" for the shared-collection add flow, so copying an item the
/// recipient already owns never creates a duplicate. Two items match when they share a non-empty
/// <c>ReferenceId</c> (both linked to the same reference document - authoritative), or, failing that, when
/// their titles normalize equal (plus a compatible year and, for books/albums, a matching creator). Reuses
/// <see cref="TitleNormalizer"/> - the same normalizer the reference layer and the importers use - so
/// "same item" never drifts between features.
/// </summary>
public static class SharedItemMatcher
{
    public static bool Matches(ItemMatchKey a, ItemMatchKey b)
    {
        if (!string.IsNullOrEmpty(a.ReferenceId) && !string.IsNullOrEmpty(b.ReferenceId))
        {
            return string.Equals(a.ReferenceId, b.ReferenceId, StringComparison.Ordinal);
        }

        if (!NormalizedEquals(a.Title, b.Title))
        {
            return false;
        }

        return CreatorCompatible(a.Creator, b.Creator) && YearCompatible(a.Year, b.Year);
    }

    /// <summary>The first item in <paramref name="existing"/> that matches, or null.</summary>
    public static T? FindMatch<T>(ItemMatchKey candidate, IEnumerable<T> existing, Func<T, ItemMatchKey> key)
        where T : class =>
        existing.FirstOrDefault(item => Matches(candidate, key(item)));

    public static bool AnyMatch(ItemMatchKey candidate, IEnumerable<ItemMatchKey> existing) =>
        existing.Any(existingKey => Matches(candidate, existingKey));

    private static bool NormalizedEquals(string a, string b) =>
        string.Equals(TitleNormalizer.Normalize(a), TitleNormalizer.Normalize(b), StringComparison.Ordinal);

    // A creator distinguishes items only when both carry one (books/albums); it never applies to the media
    // types that have no creator dimension (both null), so those fall through to title+year alone.
    private static bool CreatorCompatible(string? a, string? b) =>
        string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b) || NormalizedEquals(a, b);

    // A missing year on either side is treated as a wildcard rather than a mismatch - a tenant who never
    // recorded a year should still be told they already own the title.
    private static bool YearCompatible(int? a, int? b) => !a.HasValue || !b.HasValue || a == b;
}
