namespace Keeptrack.Domain.Models;

/// <summary>
/// How a <see cref="ShareCategory"/> is presented to the recipient and whether it can be copied. Derived
/// from the category by <see cref="Services.ShareCategoryClassifier"/> - the single place that rule lives -
/// never stored.
/// </summary>
public enum ShareKind
{
    /// <summary>Reference-linked media (movies, TV, books, albums, games): a read-only list, copyable into the recipient's own collection.</summary>
    Media,

    /// <summary>Ordinary owned collections with no shared reference to copy (collectibles, gear): a read-only list, view-only.</summary>
    Collection,

    /// <summary>Personal/sensitive data (cars, houses, health): read-only detail views, never copyable.</summary>
    Personal
}
