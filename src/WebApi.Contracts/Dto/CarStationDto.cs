using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A fuel station, shared by every account rather than owned by one - car history entries point at it by
/// id instead of each carrying their own copy of its name and location.
/// </summary>
public class CarStationDto : IHasId
{
    /// <summary>
    /// Station ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Brand/retailer name, e.g. "TotalEnergies".
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
    /// How many car history entries currently point at this station, across every account. Server-computed
    /// and read-only - it's what tells an admin whether deleting this station would strand any refuel.
    /// Only populated by the admin listing.
    /// </summary>
    public long UsageCount { get; set; }

    /// <summary>
    /// "Brand - City" (or just the brand when the city is unknown), for pickers and list rows.
    /// </summary>
    public string DisplayName => string.IsNullOrWhiteSpace(City) ? BrandName ?? "" : $"{BrandName} - {City}";
}
