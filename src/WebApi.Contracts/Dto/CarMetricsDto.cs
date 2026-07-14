using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one car: consumption, cost history, mileage warnings and next-maintenance estimate.
/// </summary>
public class CarMetricsDto
{
    /// <summary>
    /// Fuel consumption over time (L/100km), computed only across full refills.
    /// </summary>
    public required List<ConsumptionPointDto> FuelConsumption { get; set; }

    /// <summary>
    /// Average fuel consumption (L/100km), or null if there isn't enough data yet.
    /// </summary>
    public double? AverageFuelConsumptionPer100Km { get; set; }

    /// <summary>
    /// Electric consumption over time (kWh/100km), computed only across full recharges.
    /// </summary>
    public required List<ConsumptionPointDto> ElectricConsumption { get; set; }

    /// <summary>
    /// Average electric consumption (kWh/100km), or null if there isn't enough data yet.
    /// </summary>
    public double? AverageElectricConsumptionPer100Km { get; set; }

    /// <summary>
    /// Total cost of ownership, by month.
    /// </summary>
    public required List<CarCostHistoryPointDto> CostHistory { get; set; }

    /// <summary>
    /// Total cost across the whole history.
    /// </summary>
    public required double TotalCost { get; set; }

    /// <summary>
    /// Entries whose recorded mileage doesn't reconcile with their neighbors.
    /// </summary>
    public required List<CarMileageWarningDto> MileageWarnings { get; set; }

    /// <summary>
    /// Estimated next maintenance due, or null if no maintenance has been recorded yet.
    /// </summary>
    public NextMaintenanceDto? NextMaintenance { get; set; }
}
