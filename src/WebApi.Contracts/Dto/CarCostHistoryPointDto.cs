using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Total cost of ownership for one calendar month.
/// </summary>
public class CarCostHistoryPointDto
{
    /// <summary>
    /// First day of the month this point covers.
    /// </summary>
    public required DateOnly Period { get; set; }

    /// <summary>
    /// Fuel/electric spend for the month.
    /// </summary>
    public required double FuelCost { get; set; }

    /// <summary>
    /// Maintenance/other spend for the month.
    /// </summary>
    public required double MaintenanceCost { get; set; }

    /// <summary>
    /// Combined spend for the month.
    /// </summary>
    public required double TotalCost { get; set; }
}
