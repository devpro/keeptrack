using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one car: consumption, cost history, mileage warnings and last-record-per-type readout.
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
    /// When each event type was last recorded, most recent first.
    /// </summary>
    public required List<CarLastRecordDto> LastRecords { get; set; }
}

/// <summary>
/// When a car history event type was last recorded.
/// </summary>
public class CarLastRecordDto
{
    /// <summary>
    /// The event type.
    /// </summary>
    public required CarHistoryType EventType { get; set; }

    /// <summary>
    /// The most recent recorded date for that event type.
    /// </summary>
    public required DateTime LastDate { get; set; }
}
