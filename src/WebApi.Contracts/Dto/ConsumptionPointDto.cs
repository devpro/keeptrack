using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One consumption data point, always computed across a full refill or recharge.
/// </summary>
public class ConsumptionPointDto
{
    /// <summary>
    /// Date of the full refill or recharge closing this data point.
    /// </summary>
    public required DateOnly Date { get; set; }

    /// <summary>
    /// Consumption per 100 km (liters for fuel, kWh for electric).
    /// </summary>
    public required double ValuePer100Km { get; set; }
}
