using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One consumption data point, always computed across a full refill or recharge, never a partial one (see <c>CarMetricsService</c>).
/// </summary>
public class ConsumptionPointModel
{
    public required DateOnly Date { get; set; }

    public required double ValuePer100Km { get; set; }
}
