using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CarHistoryModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string CarId { get; set; }

    /// <summary>
    /// When this event happened, with its time of day.
    /// Several entries can share a date (refuels on a long road trip), and only the time sorts them in the order they happened.
    /// Midnight when the time is unknown.
    /// </summary>
    public required DateTime HistoryDate { get; set; }

    public int? Mileage { get; set; }

    public required CarHistoryType EventType { get; set; }

    public string? Description { get; set; }

    public double? Cost { get; set; }

    public string? City { get; set; }

    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    public double? Longitude { get; set; }

    public double? Latitude { get; set; }

    public string? FuelCategory { get; set; }

    public double? FuelVolume { get; set; }

    public double? FuelUnitPrice { get; set; }

    public double? ElectricVolume { get; set; }

    public double? ElectricUnitPrice { get; set; }

    public bool? IsFullRefill { get; set; }

    /// <summary>
    /// Distance driven since the previous entry, entered by the user (usually read off the trip computer at refuel time), independent of the odometer in <see cref="Mileage"/>.
    /// It is real input rather than derived, so <see cref="Domain.Services.CarMetricsService"/> can cross-check it against consecutive <see cref="Mileage"/> readings.
    /// That catches a mistyped entry or a refuel never logged.
    /// </summary>
    public double? DeltaMileage { get; set; }

    /// <summary>
    /// The <see cref="CarStationModel"/> this refuel happened at, by id.
    /// A location belongs to the station, so it is stored once there and hydrated for display, never copied onto each refuel.
    /// Refuel only, the counterpart of <see cref="Garage"/>.
    /// </summary>
    public string? StationId { get; set; }

    /// <summary>
    /// Garage name, the Maintenance and Other counterpart of <see cref="StationId"/>.
    /// Free text on the entry, since unlike a station a garage carries no location here, so there is nothing to deduplicate.
    /// </summary>
    public string? Garage { get; set; }
}
