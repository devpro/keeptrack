using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The current state of a named distributed lease (see <see cref="Repositories.ILeaseRepository"/>), read for admin diagnostics such as which replica runs the reference sync.
/// </summary>
public class LeaseModel
{
    public required string Name { get; set; }

    public required string Holder { get; set; }

    public DateTime ExpiresAt { get; set; }
}
