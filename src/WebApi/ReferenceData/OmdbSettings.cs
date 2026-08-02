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

    /// <summary>
    /// Calls allowed per UTC day across every replica, enforced by <see cref="OmdbCallBudget"/>. Defaults to
    /// OMDb's free-tier allowance; raise it here (not in code) when the key is upgraded. The scheduled
    /// consumers no longer carry hardcoded per-pass caps of their own - they spend against this one number -
    /// so this is the single knob for how much IMDb enrichment a deployment can afford.
    /// </summary>
    public int DailyCallBudget { get; set; } = 1000;

    /// <summary>
    /// How much of <see cref="DailyCallBudget"/> the scheduled passes must leave untouched, so a day of heavy
    /// backfilling can't make an admin's manual link or a user's Explore "add" come back with no IMDb rating.
    /// Small on purpose: interactive calls are one per user action, batch work is thousands.
    /// </summary>
    public int InteractiveReserve { get; set; } = 50;
}
