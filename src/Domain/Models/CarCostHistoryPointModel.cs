using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Total cost of ownership for one calendar month.
/// Energy spend and maintenance spend are kept apart as well as combined, so the UI shows a breakdown and not just a total.
/// </summary>
public class CarCostHistoryPointModel
{
    public required DateOnly Period { get; set; }

    public required double FuelCost { get; set; }

    public required double MaintenanceCost { get; set; }

    public double TotalCost => FuelCost + MaintenanceCost;
}
