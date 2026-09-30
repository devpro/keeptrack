namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Why a call is being made, which is the only thing that decides how much of the daily OMDb allowance it may
/// reach into. There is one counter, not one budget per consumer: the point is that a batch pass can drain
/// what's left *without* being able to starve a user waiting on a screen.
/// </summary>
public enum OmdbCallPriority
{
    /// <summary>A user is waiting: admin manual linking, Explore "add". May spend the whole allowance.</summary>
    Interactive,

    /// <summary>A scheduled pass: the reference sync's rating backfill, the Explore catalogue backfill. Stops short of <see cref="OmdbSettings.InteractiveReserve"/>.</summary>
    Background
}

/// <summary>
/// The gate every OMDb call passes through, enforcing the key's daily quota across replicas - see
/// <see cref="OmdbCallBudget"/> for the whole rationale and the storage shape.
/// </summary>
public interface IOmdbCallBudget
{
    /// <summary>
    /// Reserves one call, or returns false when <paramref name="priority"/>'s share of today's allowance is
    /// spent. A false answer means the caller must not call OMDb at all - and, importantly, must not record
    /// the outcome as "asked and got nothing" either, or a title would be written off over a limit that had
    /// nothing to do with it.
    /// </summary>
    Task<bool> TryReserveAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the whole allowance as spent because OMDb itself said so (HTTP 401 "Request limit reached!").
    /// That signal outranks the local count - calls may have been made outside this app, or the day's counter
    /// document may have been purged - and it must reach the other replicas, hence a shared write.
    /// </summary>
    Task MarkLimitReachedAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// How many calls <paramref name="priority"/> can still expect today. Advisory - another replica may spend
    /// between this read and the reservation - so it sizes a batch pass, it never authorizes a call.
    /// </summary>
    Task<int> GetRemainingAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether this process already knows <paramref name="priority"/>'s allowance is gone for today - a local,
    /// synchronous check a batch loop can use to stop early instead of asking the database once per remaining
    /// item. False is not a guarantee that a call will be granted; only <see cref="TryReserveAsync"/> is.
    /// </summary>
    bool IsExhausted(OmdbCallPriority priority);
}
