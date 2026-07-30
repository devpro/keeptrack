namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Fetches a title's IMDb aggregate rating from OMDb, keyed by the IMDb id TMDB already exposes
/// (<c>imdb_id</c> on a movie, <c>external_ids.imdb_id</c> on a show). The only viable source of IMDb
/// ratings - IMDb has no public ratings API - so movies/TV get their second rating source through this.
/// </summary>
public interface IOmdbClient
{
    /// <summary>
    /// The IMDb rating (already on a 0-10 scale, same as TMDB's) and vote count for <paramref name="imdbId"/>,
    /// or <c>null</c> when no OMDb key is configured, the id is unknown to OMDb, or it has no rating yet
    /// (OMDb returns <c>"N/A"</c>). Best-effort: a missing rating is "no imdb source", never an error.
    /// </summary>
    Task<OmdbRating?> GetRatingAsync(string imdbId, CancellationToken cancellationToken = default);
}

/// <summary>An IMDb aggregate rating: <paramref name="Value"/> on a 0-10 scale, with its vote <paramref name="Count"/>.</summary>
public sealed record OmdbRating(double Value, int? Count);
