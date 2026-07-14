using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

public class HouseMetricsModel
{
    public required List<HouseCostHistoryPointModel> CostHistory { get; set; }
}
