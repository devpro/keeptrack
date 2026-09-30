namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Global Explore-feature settings an admin controls - see <c>GET/PUT /api/reference-data/explore-settings</c>.
/// </summary>
public class ExploreSettingsDto
{
    /// <summary>
    /// When true, Explore ranks/shows TMDB ratings for movies and TV shows even when IMDb is the primary
    /// rating source, so discovery avoids a per-title OMDb lookup on every page load.
    /// </summary>
    public bool UseTmdbRanking { get; set; }
}
