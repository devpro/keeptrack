using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Services;

/// <summary>
/// An item's identity for "already in my collection" matching, whatever its model type.
/// <see cref="Creator"/> is the book author or album artist, null for the other types.
/// </summary>
public sealed record ItemMatchKey(string? ReferenceId, string Title, int? Year, string? Creator);

/// <summary>
/// Whether two items are the same when adding from a shared collection, so copying an item the recipient has never creates a duplicate.
/// Two items match when they share a <c>ReferenceId</c>, which is authoritative.
/// Otherwise their titles must normalize equal through <see cref="TitleNormalizer"/>, with a compatible year and, for books and albums, a matching creator.
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

    // a creator distinguishes items only when both carry one, so types without a creator match on title and year alone
    private static bool CreatorCompatible(string? a, string? b) =>
        string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b) || NormalizedEquals(a, b);

    // a missing year on either side matches anything, so a tenant who recorded no year is still told they have the title
    private static bool YearCompatible(int? a, int? b) => !a.HasValue || !b.HasValue || a == b;
}
