using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class CarHistoryModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string CarId { get; set; }

    public required DateOnly HistoryDate { get; set; }

    public int? Mileage { get; set; }

    public required CarHistoryType EventType { get; set; }

    public string? Description { get; set; }

    public double? Cost { get; set; }

    public string? City { get; set; }

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

    public string? StationBrandName { get; set; }
}
