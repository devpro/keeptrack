namespace Keeptrack.Common.System;

/// <summary>
/// List sort keys shared end-to-end: the Blazor list pages' sort picker values, the REST query contract
/// (<see cref="PagedRequest.Sort"/>) and the repositories' sort translation. No key (null/empty) means the
/// default order, newest first; a collection that doesn't support a given key falls back to that default
/// rather than erroring.
/// </summary>
public static class ListSort
{
    /// <summary>Alphabetical by the item's title/name, case- and diacritic-insensitive.</summary>
    public const string Title = "title";

    /// <summary>Best rated first; unrated items last.</summary>
    public const string Rating = "rating";
}
