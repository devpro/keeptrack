namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Body for adding an Explore suggestion to the caller's collection: its title and year create the item, then the link is made from the exact provider id in the route.
/// </summary>
public class ExploreAddRequestDto
{
    /// <summary>The suggestion's title, the created item's title before resolution replaces it with the canonical one.</summary>
    public string? Title { get; set; }

    /// <summary>The suggestion's year.</summary>
    public int? Year { get; set; }
}
