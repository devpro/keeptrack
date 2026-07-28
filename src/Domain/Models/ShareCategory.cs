namespace Keeptrack.Domain.Models;

/// <summary>
/// One category of a user's collection that can be shared as a whole with another user. Sharing is
/// category-level (never per-item), so a grant carries a set of these. Its <see cref="WebApi.Contracts"/>
/// twin must keep identical member names (mapped by name), like every other Domain/Contracts enum pair.
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
