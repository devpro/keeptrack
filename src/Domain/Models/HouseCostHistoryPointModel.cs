using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Total cost of ownership for one calendar year, both as a single total and broken down by event category -
/// see <see cref="Services.HouseMetricsService"/>.
/// </summary>
public class HouseCostHistoryPointModel
{
    public required int Year { get; set; }

    public required double TotalCost { get; set; }

    public required List<HouseCategoryCostModel> CostByCategory { get; set; }
}
