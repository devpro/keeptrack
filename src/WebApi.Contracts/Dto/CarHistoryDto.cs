using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Car history data transfer object.
/// </summary>
public class CarHistoryDto : IHasId
{
    /// <summary>
    /// History ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Car ID.
    /// </summary>
    public required string CarId { get; set; }

    /// <summary>
    /// History date and time.
    /// Several entries can share a date (refuels on a road trip), and the time sorts them.
    /// Midnight when the time is unknown.
    /// </summary>
    public required DateTime HistoryDate { get; set; }

    /// <summary>
    /// Mileage indicated on the car.
    /// </summary>
    public int? Mileage { get; set; }

    /// <summary>
    /// Event type (Refuel, Maintenance, Other).
    /// </summary>
    public required CarHistoryType EventType { get; set; }

    /// <summary>
    /// Free-text description of what was done, the main field of Maintenance and Other events.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Total cost of this event (a fill-up, an invoice).
    /// </summary>
    public double? Cost { get; set; }

    /// <summary>
    /// City.
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
    /// Fuel category, such as Diesel or SP95.
    /// </summary>
    public string? FuelCategory { get; set; }

    /// <summary>
    /// Fuel volume (L).
    /// </summary>
    public double? FuelVolume { get; set; }

    /// <summary>
    /// Fuel unit price (per L).
    /// </summary>
    public double? FuelUnitPrice { get; set; }

    /// <summary>
    /// Electric energy added (kWh).
    /// </summary>
    public double? ElectricVolume { get; set; }

    /// <summary>
    /// Electric unit price (per kWh).
    /// </summary>
    public double? ElectricUnitPrice { get; set; }

    /// <summary>
    /// Whether the tank or battery was filled completely.
    /// </summary>
    public bool? IsFullRefill { get; set; }

    /// <summary>
    /// Distance driven since the previous entry, entered by the user from the trip computer, independent of <see cref="Mileage"/> and used to cross-check it.
    /// </summary>
    public double? DeltaMileage { get; set; }

    /// <summary>
    /// The shared <see cref="CarStationDto"/> this refuel happened at, by id.
    /// The station holds its city, postal code and coordinates, so a refuel carries no copy of them.
    /// </summary>
    public string? StationId { get; set; }

    /// <summary>
    /// Brand name of <see cref="StationId"/>'s station.
    /// Hydrated by the server for display and ignored on write, with one batched station lookup per page.
    /// </summary>
    public string? StationBrandName { get; set; }

    /// <summary>
    /// City of <see cref="StationId"/>'s station.
    /// Hydrated by the server for display, like <see cref="StationBrandName"/>.
    /// </summary>
    public string? StationCity { get; set; }

    /// <summary>
    /// Garage name, the Maintenance and Other counterpart of <see cref="StationId"/>.
    /// </summary>
    public string? Garage { get; set; }
}
