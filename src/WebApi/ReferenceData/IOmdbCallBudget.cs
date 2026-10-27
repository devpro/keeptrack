namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Why a call is made, which alone decides how much of the daily OMDb allowance it may use.
/// One counter rather than a budget per consumer, so a batch pass drains what is left without starving a user waiting on a screen.
/// </summary>
public enum OmdbCallPriority
{
    /// <summary>A user is waiting (admin linking, Explore's add), so it may spend the whole allowance.</summary>
    Interactive,

    /// <summary>A scheduled pass (the reference sync's and Explore's backfills), stopping short of <see cref="OmdbSettings.InteractiveReserve"/>.</summary>
    Background
}

/// <summary>
/// The gate of every OMDb call, enforcing the key's daily quota across replicas (see <see cref="OmdbCallBudget"/>).
/// </summary>
public interface IOmdbCallBudget
{
    /// <summary>
    /// Reserves one call, or returns false when <paramref name="priority"/>'s share of today's allowance is spent.
    /// The caller then neither calls OMDb nor records "asked and got nothing", or a title would be written off over an unrelated limit.
    /// </summary>
    Task<bool> TryReserveAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the whole allowance as spent because OMDb said so (401 "Request limit reached!").
    /// That outranks the local count, since calls may come from outside this app or the counter may be lost, and a shared write tells the other replicas.
    /// </summary>
    Task MarkLimitReachedAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// How many calls <paramref name="priority"/> can still expect today.
    /// Advisory, since another replica may spend in between, so it sizes a batch but never authorizes a call.
    /// </summary>
    Task<int> GetRemainingAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether this process already knows <paramref name="priority"/>'s allowance is spent today, a local check letting a batch stop early without asking the database per item.
    /// False guarantees nothing, only <see cref="TryReserveAsync"/> does.
    /// </summary>
    bool IsExhausted(OmdbCallPriority priority);
}
