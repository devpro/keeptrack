using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class HouseModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public required string City { get; set; }

    public required PropertyType PropertyType { get; set; }

    /// <summary>When the owner moved into this property, if recorded.</summary>
    public DateOnly? MovedInAt { get; set; }

    /// <summary>When the owner moved out of this property, if recorded (unset while still occupied).</summary>
    public DateOnly? MovedOutAt { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
