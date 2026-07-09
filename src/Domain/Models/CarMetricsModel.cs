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

    public NextMaintenanceModel? NextMaintenance { get; set; }
}
