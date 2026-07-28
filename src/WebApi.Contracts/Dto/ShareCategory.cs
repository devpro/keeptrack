namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One category of a collection that can be shared as a whole with another user. The Contracts twin of
/// the Domain <c>ShareCategory</c> enum (Contracts can't reference Domain); member names are kept
/// identical and mapped by name.
/// </summary>
public enum ShareCategory
{
    /// <summary>The caller's movies.</summary>
    Movies,

    /// <summary>The caller's TV shows.</summary>
    TvShows,

    /// <summary>The caller's books.</summary>
    Books,

    /// <summary>The caller's albums.</summary>
    Albums,

    /// <summary>The caller's video games.</summary>
    VideoGames,

    /// <summary>The caller's cars (personal - view-only, never copyable).</summary>
    Cars,

    /// <summary>The caller's houses (personal - view-only, never copyable).</summary>
    Houses,

    /// <summary>The caller's health journal (personal - view-only, never copyable).</summary>
    Health
}
