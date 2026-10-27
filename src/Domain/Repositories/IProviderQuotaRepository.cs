using System;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// A shared daily call counter for a rate-limited provider, so replicas spending one API key cannot together exceed its quota.
/// One document per (provider, UTC day), incremented atomically, with MongoDB as the coordination primitive like <see cref="ILeaseRepository"/>.
/// An in-process counter would let each replica spend the whole daily allowance.
/// <para>
/// The day is part of the key rather than a value to reset, so the allowance renews with no scheduled job and no clock coordination beyond agreeing on the UTC day.
/// </para>
/// </summary>
public interface IProviderQuotaRepository
{
    /// <summary>
    /// Atomically reserves one call against <paramref name="provider"/>'s allowance for <paramref name="day"/>.
    /// False when the count already reached <paramref name="ceiling"/>, and the caller must then not make the call.
    /// <para>
    /// The ceiling is passed per call rather than stored, so part of the allowance is held back for higher-priority work:
    /// a background consumer passes a lower ceiling than a user-facing one against the same counter.
    /// </para>
    /// </summary>
    Task<bool> TryConsumeAsync(string provider, DateOnly day, int ceiling, CancellationToken cancellationToken = default);

    /// <summary>
    /// How many calls are reserved so far for <paramref name="provider"/> on <paramref name="day"/>, so a batch sizes its pass to what is left.
    /// Advisory only, since another replica can spend at any moment, so a real call still goes through <see cref="TryConsumeAsync"/>.
    /// </summary>
    Task<int> GetUsedAsync(string provider, DateOnly day, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the whole allowance as spent, when the provider itself reports its limit reached.
    /// That signal is authoritative and can come before the local count expects it, after calls made outside this app or a lost counter document.
    /// It never lowers the count, so it cannot undo concurrent reservations.
    /// </summary>
    Task ExhaustAsync(string provider, DateOnly day, int total, CancellationToken cancellationToken = default);
}
