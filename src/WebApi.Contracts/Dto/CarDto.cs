using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Car data transfer object.
/// </summary>
public class CarDto : IHasId
{
    /// <summary>
    /// Car ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Car name.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Manufacturer.
    /// </summary>
    public string? Manufacturer { get; set; }

    /// <summary>
    /// Model.
    /// </summary>
    public string? Model { get; set; }

    /// <summary>
    /// Year.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>
    /// License plate.
    /// </summary>
    public string? LicensePlate { get; set; }

    /// <summary>
    /// Energy type (Combustion, Hybrid, Electric).
    /// </summary>
    public CarEnergyType? EnergyType { get; set; }

    /// <summary>
    /// Tenant-owned cover image URL, shown on the list thumbnail and detail page header. Optional.
    /// </summary>
    public string? ImageUrl { get; set; }
}
