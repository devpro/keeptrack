using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

public class CarMetricsModel
{
    public required List<ConsumptionPointModel> FuelConsumption { get; set; }

    public double? AverageFuelConsumptionPer100Km { get; set; }

    public required List<ConsumptionPointModel> ElectricConsumption { get; set; }

    public double? AverageElectricConsumptionPer100Km { get; set; }

    public required List<CarCostHistoryPointModel> CostHistory { get; set; }

    public required double TotalCost { get; set; }

    public required List<CarMileageWarningModel> MileageWarnings { get; set; }

    public required List<CarLastRecordModel> LastRecords { get; set; }
}

/// <summary>
/// "When did I last log each kind of car event" - one line per <see cref="CarHistoryType"/>. Same shape as
/// <see cref="HealthLastVisitModel"/>, keyed by the discriminated event-type enum instead of a free-text specialty.
/// </summary>
public class CarLastRecordModel
{
    public required CarHistoryType EventType { get; set; }

    public required DateTime LastDate { get; set; }
}
