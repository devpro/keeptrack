namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Body for adding an Explore suggestion to the caller's collection - the suggestion's own title and year,
/// used to create the item; the reference link is then made from the exact TMDB id in the route.
/// </summary>
public class ExploreAddRequestDto
{
    /// <summary>The suggestion's title (the created item's title, before reference resolution canonicalizes it).</summary>
    public string? Title { get; set; }

    /// <summary>The suggestion's year.</summary>
    public int? Year { get; set; }
}
