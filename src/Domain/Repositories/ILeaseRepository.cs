using System;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// A minimal distributed lease, so work that must run on one replica at a time (the reference sync) elects a runner with no external scheduler.
/// Best effort within the database clock's precision: enough to deduplicate a daily job, not a general lock.
/// </summary>
public interface ILeaseRepository
{
    /// <summary>
    /// Atomically acquires the named lease, or renews it for its holder, until now plus <paramref name="duration"/>.
    /// False when another holder's lease is still live.
    /// </summary>
    Task<bool> TryAcquireAsync(string name, string holderId, TimeSpan duration);

    /// <summary>
    /// The named lease's holder and expiry, live or not, or null when never acquired, for admin diagnostics only.
    /// </summary>
    Task<LeaseModel?> FindAsync(string name);
}
