namespace Keeptrack.Domain.Models;

/// <summary>
/// The domain an Explore action applies to.
/// Only domains with a meaningful provider ranking appear: books and albums have no best-of listing.
/// The controller maps it from the <c>ReferenceItemType</c> DTO enum.
/// </summary>
public enum ExploreItemType
{
    Movie,
    TvShow,
    VideoGame
}
