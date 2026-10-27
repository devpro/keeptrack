namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Fetches a title's IMDb rating from OMDb, keyed by the IMDb id TMDB exposes (<c>imdb_id</c> on a movie, <c>external_ids.imdb_id</c> on a show).
/// The only source of IMDb ratings, since IMDb has no public ratings API.
/// </summary>
public interface IOmdbClient
{
    /// <summary>
    /// Looks up <paramref name="imdbId"/>'s IMDb rating, on TMDB's 0 to 10 scale, within the daily budget of <paramref name="priority"/> (see <see cref="OmdbCallBudget"/>).
    /// <para>
    /// Never throws for anything OMDb or the network does: an unknown id, an unrated title, a spent quota, a timeout and a 5xx are all results.
    /// IMDb is best effort, and a missing rating must never fail an admin's link or an Explore add.
    /// The distinction that matters is <see cref="OmdbLookupResult.Attempted"/>.
    /// </para>
    /// </summary>
    Task<OmdbLookupResult> GetRatingAsync(string imdbId, OmdbCallPriority priority, CancellationToken cancellationToken = default);
}

/// <summary>An IMDb aggregate rating: <paramref name="Value"/> on a 0-10 scale, with its vote <paramref name="Count"/>.</summary>
public sealed record OmdbRating(double Value, int? Count);

/// <summary>
/// The outcome of one lookup.
/// <paramref name="Attempted"/> is what matters.
/// "OMDb answered with no rating" is a fact worth recording, so a backfill stops asking about unrated titles.
/// "Never asked" (no key, no budget, a timeout) leaves no trace, or one exhausted afternoon would write those titles off for months.
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
