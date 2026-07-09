using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One consumption data point, always computed across a full refill/recharge.
/// </summary>
public class ConsumptionPointDto
{
    /// <summary>
    /// Date of the full refill/recharge that closed this data point.
    /// </summary>
    public required DateOnly Date { get; set; }

    /// <summary>
    /// Consumption per 100 km (liters for fuel, kWh for electric).
    /// </summary>
    public required double ValuePer100Km { get; set; }
}
