using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Total cost of ownership for one calendar month - fuel/electric spend and maintenance/other spend tracked
/// separately as well as combined, so the UI can show a breakdown, not just a total.
/// </summary>
public class CarCostHistoryPointModel
{
    public required DateOnly Period { get; set; }

    public required double FuelCost { get; set; }

    public required double MaintenanceCost { get; set; }

    public double TotalCost => FuelCost + MaintenanceCost;
}
