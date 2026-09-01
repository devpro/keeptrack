namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Fetches a title's IMDb aggregate rating from OMDb, keyed by the IMDb id TMDB already exposes
/// (<c>imdb_id</c> on a movie, <c>external_ids.imdb_id</c> on a show). The only viable source of IMDb
/// ratings - IMDb has no public ratings API - so movies/TV get their second rating source through this.
/// </summary>
public interface IOmdbClient
{
    /// <summary>
    /// Looks up <paramref name="imdbId"/>'s IMDb rating (already on a 0-10 scale, same as TMDB's), subject to
    /// the daily call budget for <paramref name="priority"/> - see <see cref="OmdbCallBudget"/>.
    /// <para>
    /// Never throws for anything OMDb or the network can do to us: an unknown id, an unrated title, a spent
    /// quota, a timeout and a 5xx all come back as a result rather than an exception, because every caller
    /// treats IMDb as best-effort and a missing rating must never be able to fail an admin's manual link or a
    /// user's Explore "add". The distinction that does matter is carried by
    /// <see cref="OmdbLookupResult.Attempted"/>.
    /// </para>
    /// </summary>
    Task<OmdbLookupResult> GetRatingAsync(string imdbId, OmdbCallPriority priority, CancellationToken cancellationToken = default);
}

/// <summary>An IMDb aggregate rating: <paramref name="Value"/> on a 0-10 scale, with its vote <paramref name="Count"/>.</summary>
public sealed record OmdbRating(double Value, int? Count);

/// <summary>
/// The outcome of one lookup. <paramref name="Attempted"/> is the load-bearing half: "OMDb answered and has
/// no rating for this title" is a fact worth recording (it's what lets a backfill stop re-asking about the
/// same handful of genuinely unrated titles), whereas "we never got to ask" - no API key, no budget left, a
/// timeout - must leave no trace at all, or one exhausted afternoon would write those titles off for months.
/// </summary>
public sealed record OmdbLookupResult(bool Attempted, OmdbRating? Rating)
{
    /// <summary>OMDb was not called: no key configured, the daily budget is spent, or the call failed.</summary>
    public static OmdbLookupResult NotAttempted { get; } = new(false, null);

    /// <summary>OMDb answered, and has no rating for this title.</summary>
    public static OmdbLookupResult NoRating { get; } = new(true, null);

    /// <summary>OMDb answered with a rating.</summary>
    public static OmdbLookupResult Rated(OmdbRating rating) => new(true, rating);
}
