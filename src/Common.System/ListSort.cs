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

    /// <summary>Most recently watched movie first (Movie's <c>FirstSeenAt</c>); unwatched items last.</summary>
    public const string LastSeen = "seen";

    /// <summary>Most recently read book first (Book's <c>FirstReadAt</c>); unread items last.</summary>
    public const string LastRead = "read";

    /// <summary>Most recently completed video game first (max <c>CompletedAt</c> across a game's platform entries); items with none last.</summary>
    public const string LastCompleted = "completed";

    /// <summary>Most recently bought gear first (max <c>AcquiredAt</c> across a gear item's owned versions); items with none last.</summary>
    public const string Bought = "bought";
}
