namespace Keeptrack.Domain.Models;

/// <summary>
/// Which reference-ranked domain an Explore ("suggest top-rated, not-yet-added") action applies to.
/// Only the domains where a provider ranking is meaningful appear here - movies/TV today, video games
/// next; books and albums are deliberately excluded (an aggregate rank doesn't drive discovery there).
/// The Domain-side counterpart of the <c>ReferenceItemType</c> DTO enum, mapped by name in the controller.
/// </summary>
public enum ExploreItemType
{
    Movie,
    TvShow,
    VideoGame
}
