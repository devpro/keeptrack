using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CarModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public string? Manufacturer { get; set; }

    public string? Model { get; set; }

    public int? Year { get; set; }

    public string? LicensePlate { get; set; }

    public required CarEnergyType EnergyType { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
