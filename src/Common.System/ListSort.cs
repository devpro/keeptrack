namespace Keeptrack.Common.System;

/// <summary>
/// List sort keys shared end to end: the list pages' sort picker, the REST query contract (<see cref="PagedRequest.Sort"/>) and the repositories.
/// No key means the default order, newest first.
/// A collection that does not support a key falls back to that default rather than failing.
/// </summary>
public static class ListSort
{
    /// <summary>Alphabetical by the item's title/name, case- and diacritic-insensitive.</summary>
    public const string Title = "title";

    /// <summary>Best rated first; unrated items last.</summary>
    public const string Rating = "rating";

    /// <summary>
    /// Best rated first by the provider rating, the <c>ReferenceRating</c> copied onto the item on link and refresh, with unrated items last.
    /// Distinct from <see cref="Rating"/>, which is the user's own star rating.
    /// </summary>
    public const string ReferenceRating = "refrating";

    /// <summary>Most recently watched movie first (Movie's <c>FirstSeenAt</c>); unwatched items last.</summary>
    public const string LastSeen = "seen";

    /// <summary>Most recently read book first (Book's <c>FirstReadAt</c>); unread items last.</summary>
    public const string LastRead = "read";

    /// <summary>Most recently completed video game first (max <c>CompletedAt</c> across a game's platform entries); items with none last.</summary>
    public const string LastCompleted = "completed";

    /// <summary>Most recently bought gear first (max <c>AcquiredAt</c> across a gear item's owned versions); items with none last.</summary>
    public const string Bought = "bought";
}
