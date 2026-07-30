namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// OMDb is the source of IMDb aggregate ratings (IMDb itself has no public ratings API) - see
/// <see cref="OmdbClient"/>. Unlike every other provider's settings, <see cref="ApiKey"/> is optional
/// (nullable, not <c>required</c>): IMDb enrichment is best-effort, so a deployment with no OMDb key simply
/// keeps movies/TV on their TMDB rating alone rather than failing resolution/refresh.
/// </summary>
public class OmdbSettings
{
    public string? ApiKey { get; set; }
}
