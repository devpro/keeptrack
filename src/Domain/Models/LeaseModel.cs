using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A named distributed lease's current state (see <see cref="Repositories.ILeaseRepository"/>) -
/// read for admin diagnostics ("who is running the reference sync"), never mutated through this shape.
/// </summary>
public class LeaseModel
{
    public required string Name { get; set; }

    public required string Holder { get; set; }

    public DateTime ExpiresAt { get; set; }
}
