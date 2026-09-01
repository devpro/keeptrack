using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Test double for OMDb (IMDb ratings): returns a rating for any imdb id seeded in <see cref="Ratings"/>,
/// and records which ids were queried so a test can assert the cheap backfill did or didn't call the
/// provider. An id with no seeded rating answers <see cref="OmdbLookupResult.NoRating"/> ("OMDb was asked and
/// has nothing"); set <see cref="Unavailable"/> for the other kind of empty answer - no key, no budget left,
/// a failed request - which callers must treat as "never asked".
/// </summary>
internal sealed class FakeOmdbClient : IOmdbClient
{
    public Dictionary<string, OmdbRating> Ratings { get; } = new();

    public List<string> Requested { get; } = [];

    public List<OmdbCallPriority> Priorities { get; } = [];

    /// <summary>When true every lookup comes back not-attempted, as it does with no key or a failed request.</summary>
    public bool Unavailable { get; set; }

    /// <summary>
    /// The shared allowance this client spends from, when a test cares about it. Only
    /// <see cref="ReportsLimitReached"/> uses it.
    /// </summary>
    public IOmdbCallBudget? Budget { get; set; }

    /// <summary>
    /// When true a lookup answers the way OMDb's "Request limit reached!" 401 does: the day is written off on
    /// <see cref="Budget"/> and the call comes back not-attempted. That is the case a caller's own pre-call
    /// budget guard cannot catch - the allowance was still open when the call started (another replica had
    /// spent it, or this was the call that hit the ceiling), so exhaustion is only observable afterwards.
    /// </summary>
    public bool ReportsLimitReached { get; set; }

    public static FakeOmdbClient Empty() => new();

    public async Task<OmdbLookupResult> GetRatingAsync(string imdbId, OmdbCallPriority priority, CancellationToken cancellationToken = default)
    {
        if (Unavailable) return OmdbLookupResult.NotAttempted;
        if (ReportsLimitReached)
        {
            if (Budget is not null) await Budget.MarkLimitReachedAsync(cancellationToken);
            return OmdbLookupResult.NotAttempted;
        }

        Requested.Add(imdbId);
        Priorities.Add(priority);
        return Ratings.TryGetValue(imdbId, out var rating)
            ? OmdbLookupResult.Rated(rating)
            : OmdbLookupResult.NoRating;
    }
}

/// <summary>
/// Test double for the daily OMDb allowance. Defaults to "plenty left" so the many tests that don't care
/// about quota read as if it didn't exist; <see cref="Remaining"/> and <see cref="Exhausted"/> let the ones
/// that do care pin the budget-aware behaviour.
/// </summary>
internal sealed class FakeOmdbCallBudget : IOmdbCallBudget
{
    public int Remaining { get; set; } = int.MaxValue;

    public bool Exhausted { get; set; }

    public int Reserved { get; private set; }

    public bool LimitReported { get; private set; }

    public Task<bool> TryReserveAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default)
    {
        if (Exhausted) return Task.FromResult(false);
        Reserved++;
        return Task.FromResult(true);
    }

    public Task MarkLimitReachedAsync(CancellationToken cancellationToken = default)
    {
        LimitReported = true;
        Exhausted = true;
        return Task.CompletedTask;
    }

    public Task<int> GetRemainingAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default) =>
        Task.FromResult(Exhausted ? 0 : Remaining);

    public bool IsExhausted(OmdbCallPriority priority) => Exhausted;
}
