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
    /// History date and time. Several entries can share the same date (e.g. multiple refuels on a road
    /// trip); the time is what lets them sort correctly. Defaults to midnight when the time isn't known.
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
    /// Free-text description of what was done - the main field for Maintenance/Other events.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Total cost of this event (fuel/electric fill-up, invoice, ...).
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
    /// Fuel category (e.g. Diesel, SP95).
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
    /// Is this a full tank / full charge refill?
    /// </summary>
    public bool? IsFullRefill { get; set; }

    /// <summary>
    /// Distance driven since the previous entry, as recorded by the user (e.g. from the car's trip computer) -
    /// independent of the odometer reading in <see cref="Mileage"/>, used to cross-check it.
    /// </summary>
    public double? DeltaMileage { get; set; }

    /// <summary>
    /// The shared <see cref="CarStationDto"/> this Refuel happened at, by id. The station owns its own
    /// city, postal code and coordinates, so a refuel no longer carries a copy of them.
    /// </summary>
    public string? StationId { get; set; }

    /// <summary>
    /// Brand name of <see cref="StationId"/>'s station. Server-hydrated for display and ignored on write -
    /// one batched station lookup per list page, never one per entry.
    /// </summary>
    public string? StationBrandName { get; set; }

    /// <summary>
    /// City of <see cref="StationId"/>'s station. Server-hydrated for display, like
    /// <see cref="StationBrandName"/>.
    /// </summary>
    public string? StationCity { get; set; }

    /// <summary>
    /// Garage/auto shop name - the Maintenance/Other-event counterpart of <see cref="StationId"/>.
    /// </summary>
    public string? Garage { get; set; }
}
