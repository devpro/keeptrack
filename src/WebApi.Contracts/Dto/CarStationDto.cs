using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A fuel station, shared by every account, which car history entries point at by id rather than each copying its name and location.
/// </summary>
public class CarStationDto : IHasId
{
    /// <summary>
    /// Station ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Brand or retailer name, such as "TotalEnergies".
    /// </summary>
    public string? BrandName { get; set; }

    /// <summary>
    /// City the station is in.
    /// </summary>
    public string? City { get; set; }

    /// <summary>
    /// Postal code.
    /// </summary>
    public string? PostalCode { get; set; }

    /// <summary>
    /// Country.
    /// </summary>
    public string? Country { get; set; }

    /// <summary>
    /// Longitude.
    /// </summary>
    public double? Longitude { get; set; }

    /// <summary>
    /// Latitude.
    /// </summary>
    public double? Latitude { get; set; }

    /// <summary>
    /// How many car history entries of every account point at this station.
    /// Read-only, computed by the server for the admin listing only, so an admin sees whether deleting the station would strand a refuel.
    /// </summary>
    public long UsageCount { get; set; }

    /// <summary>
    /// "Brand - City", or the brand alone when the city is unknown, for pickers and list rows.
    /// </summary>
    public string DisplayName => string.IsNullOrWhiteSpace(City) ? BrandName ?? "" : $"{BrandName} - {City}";
}
