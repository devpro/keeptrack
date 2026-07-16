using System;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// A minimal distributed lease, so work that must run on exactly one replica at a time (the periodic
/// reference sync) can elect a runner without any external scheduler or dedicated deployment.
/// Best-effort within database clock precision - fine for deduplicating a daily job, not a general lock.
/// </summary>
public interface ILeaseRepository
{
    /// <summary>
    /// Atomically acquires (or renews, for the current holder) the named lease until now + duration.
    /// Returns false when another holder's lease is still live.
    /// </summary>
    Task<bool> TryAcquireAsync(string name, string holderId, TimeSpan duration);

    /// <summary>
    /// The named lease's current state (holder and expiry, live or not), or null when it has never been
    /// acquired - admin diagnostics only, never part of the acquisition logic.
    /// </summary>
    Task<LeaseModel?> FindAsync(string name);
}
