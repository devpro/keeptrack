namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Global Explore settings an admin controls, see <c>GET/PUT /api/reference-data/explore-settings</c>.
/// </summary>
public class ExploreSettingsDto
{
    /// <summary>
    /// When true, Explore shows TMDB ratings for movies and TV shows even when IMDb is the primary source, avoiding an OMDb lookup per title.
    /// </summary>
    public bool UseTmdbRanking { get; set; }
}
