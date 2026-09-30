using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CarHistoryModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string CarId { get; set; }

    /// <summary>
    /// When this event happened. Carries a real time-of-day, not just a calendar day - several entries
    /// (e.g. multiple refuels on a long road trip) can share the same date, and only the time lets them
    /// sort in the order they actually happened. Defaults to midnight when the time isn't known.
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
    /// Distance driven since the previous history entry, as recorded by the user directly (typically read off
    /// the car's own trip computer at refuel time) - independent of the odometer reading in <see cref="Mileage"/>.
    /// Kept deliberately as real input, not derived: <see cref="Domain.Services.CarMetricsService"/> cross-checks
    /// it against consecutive <see cref="Mileage"/> readings to catch a mistyped entry or a refuel that was never
    /// logged at all - the same manual check the user used to do by hand in a spreadsheet.
    /// </summary>
    public double? DeltaMileage { get; set; }

    /// <summary>
    /// The <see cref="CarStationModel"/> this Refuel happened at, by id. Replaces the free-text station
    /// brand name every entry used to carry alongside its own copy of the station's city, postal code and
    /// coordinates: that location is a property of the station, so it is stored once there and hydrated
    /// for display, never duplicated per refuel (see <c>scripts/migrate-car-history-station.js</c>).
    /// Refuel-only, the counterpart of <see cref="Garage"/>.
    /// </summary>
    public string? StationId { get; set; }

    /// <summary>
    /// Garage/auto shop name - the Maintenance/Other-event counterpart of <see cref="StationId"/>
    /// (which only applies to Refuel events). Deliberately still free text on the entry: unlike a fuel
    /// station, a garage carries no location of its own here, so there is nothing to de-duplicate.
    /// </summary>
    public string? Garage { get; set; }
}
