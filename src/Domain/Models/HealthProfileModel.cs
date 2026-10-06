using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Whose health journal this is, the parent of <see cref="HealthRecordModel"/> as a car is of its history.
/// One per person: usually the account owner, but a household tracking a child's or partner's appointments creates one profile each, like owning two cars.
/// </summary>
public class HealthProfileModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// The tenant's own optional cover image URL, shown on the list thumbnail and the detail page header.
    /// </summary>
    public string? ImageUrl { get; set; }
}
