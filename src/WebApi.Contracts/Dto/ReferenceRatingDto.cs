namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One aggregate rating from a single source, the value of a reference DTO's <c>Ratings</c> map (keyed
/// by source name, e.g. "tmdb"). <see cref="Value"/> is on the source's own <see cref="Scale"/>
/// (10 for TMDB); never normalized across sources.
/// </summary>
public class ReferenceRatingDto
{
    /// <summary>The rating value, on <see cref="Scale"/> (e.g. 7.8 out of 10).</summary>
    public double Value { get; set; }

    /// <summary>The maximum of the source's scale (e.g. 10 for TMDB, 5 for RAWG, 100 for Metacritic).</summary>
    public double Scale { get; set; }

    /// <summary>Number of votes the value aggregates, when the source reports it.</summary>
    public int? Count { get; set; }
}
