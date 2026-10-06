namespace Keeptrack.Domain.Models;

/// <summary>
/// One category of a user's collection that can be shared as a whole with another user.
/// Sharing is by category, never per item, so a grant carries a set of these.
/// </summary>
public enum ShareCategory
{
    Movies,
    TvShows,
    Books,
    Albums,
    VideoGames,
    Collectibles,
    Gears,
    Cars,
    Houses,
    Health
}
