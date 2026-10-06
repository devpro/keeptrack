namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// OMDb supplies IMDb ratings, since IMDb has no public ratings API (see <see cref="OmdbClient"/>).
/// <see cref="ApiKey"/> is optional, since IMDb ratings are best effort: without a key, movies and TV keep their TMDB rating alone.
/// </summary>
public class OmdbSettings
{
    public string? ApiKey { get; set; }

    /// <summary>
    /// Calls allowed per UTC day across every replica, enforced by <see cref="OmdbCallBudget"/>.
    /// OMDb's free tier by default, raised in configuration for an upgraded key.
    /// Every consumer spends against this one number, the single knob for how much IMDb data a deployment affords.
    /// </summary>
    public int DailyCallBudget { get; set; } = 1000;

    /// <summary>
    /// How much of <see cref="DailyCallBudget"/> the scheduled passes leave, so heavy backfilling never leaves an admin's link or an Explore add without an IMDb rating.
    /// Small, since an interactive call is one per user action, where batch work is thousands.
    /// </summary>
    public int InteractiveReserve { get; set; } = 50;
}
