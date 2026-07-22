using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Whose health journal this is - the Car/House-style parent of <see cref="HealthRecordModel"/>.
/// One per person: typically just the account owner, but a household tracking a child's or partner's
/// appointments creates one profile each, exactly like owning two cars.
/// </summary>
public class HealthProfileModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
