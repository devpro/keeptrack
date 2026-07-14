using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One external-provider search candidate (TMDB, Open Library, RAWG or Discogs, depending on the request's
/// <see cref="ReferenceItemType"/>), shown to an admin picking the right match for an unresolved title.
/// Cover art and top cast names (TV/movie only) help distinguish near-identical candidates (e.g. remakes,
/// regional variants).
/// </summary>
public class ReferenceSearchResultDto
{
    public required string ExternalId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? ImageUrl { get; set; }

    /// <summary>
    /// Book author or album artist - null for TV shows/movies/video games, which have no single-name
    /// creator concept exposed here (TV/movie use <see cref="TopCastNames"/> instead).
    /// </summary>
    public string? Creator { get; set; }

    public List<string> TopCastNames { get; set; } = [];
}
