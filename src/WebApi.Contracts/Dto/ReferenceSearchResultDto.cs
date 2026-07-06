namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One TMDB search candidate, shown to an admin picking the right match for an unresolved title.
/// </summary>
public class ReferenceSearchResultDto
{
    public required string TmdbId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }
}
