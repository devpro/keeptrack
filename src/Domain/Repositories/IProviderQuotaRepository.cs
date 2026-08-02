using System;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// A shared daily call counter for a rate-limited third-party provider, so several WebApi replicas spending
/// the same API key can't collectively exceed its quota. One document per (provider, UTC day), incremented
/// atomically - the same "let MongoDB be the coordination primitive" approach as
/// <see cref="ILeaseRepository"/>, and for the same reason: an in-process counter is per-replica, and n
/// replicas would each happily spend the whole daily allowance.
/// <para>
/// The day is part of the key rather than a value that gets reset, so the allowance renews on its own with
/// no scheduled job and no clock coordination beyond "everyone agrees what UTC day it is".
/// </para>
/// </summary>
public interface IProviderQuotaRepository
{
    /// <summary>
    /// Atomically reserves one call against <paramref name="provider"/>'s allowance for <paramref name="day"/>,
    /// returning false when the count has already reached <paramref name="ceiling"/> - in which case the
    /// caller must not make the call at all.
    /// <para>
    /// The ceiling is supplied per call rather than stored, which is what lets a caller hold part of the
    /// allowance back for higher-priority work: a low-priority consumer simply passes a lower ceiling than a
    /// user-facing one against the very same counter.
    /// </para>
    /// </summary>
    Task<bool> TryConsumeAsync(string provider, DateOnly day, int ceiling, CancellationToken cancellationToken = default);

    /// <summary>
    /// How many calls have been reserved so far for <paramref name="provider"/> on <paramref name="day"/>
    /// (0 when nothing has been). Lets a batch consumer size a pass to what's actually left instead of a
    /// hardcoded guess. Advisory only - it can go stale the moment another replica spends, so an actual call
    /// must still go through <see cref="TryConsumeAsync"/>.
    /// </summary>
    Task<int> GetUsedAsync(string provider, DateOnly day, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the whole allowance as spent, for when the provider itself reports the limit reached - the
    /// authoritative signal, which can arrive before the local count expects it (calls made outside this app,
    /// or a counter document lost/purged). Never lowers the count, so it can't undo concurrent reservations.
    /// </summary>
    Task ExhaustAsync(string provider, DateOnly day, int total, CancellationToken cancellationToken = default);
}
