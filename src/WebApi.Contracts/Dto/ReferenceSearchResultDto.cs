using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One TMDB search candidate, shown to an admin picking the right match for an unresolved title.
/// Poster and top cast names help distinguish near-identical candidates (e.g. remakes, regional variants).
/// </summary>
public class ReferenceSearchResultDto
{
    public required string TmdbId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? PosterUrl { get; set; }

    public List<string> TopCastNames { get; set; } = [];
}
