using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Pure, stateless computation over a house's history - no persistence of its own, same shape as
/// <see cref="CarMetricsService"/>/<see cref="WatchNextService"/>. Deliberately limited to a yearly cost
/// breakdown: House has no reminders/due-date engine (unlike Car's ComputeNextMaintenanceDue) by design -
/// the owner tracks recurring bills/maintenance elsewhere and only wants an exhaustive record plus a yearly
/// cost review here.
/// </summary>
public class HouseMetricsService
{
    public HouseMetricsModel ComputeMetrics(IEnumerable<HouseHistoryModel> history) =>
        new() { CostHistory = ComputeAnnualCostHistory(history) };

    private static List<HouseCostHistoryPointModel> ComputeAnnualCostHistory(IEnumerable<HouseHistoryModel> history) =>
        history
            .Where(h => h.Cost is not null)
            .GroupBy(h => h.HistoryDate.Year)
            .OrderBy(g => g.Key)
            .Select(g => new HouseCostHistoryPointModel
            {
                Year = g.Key,
                TotalCost = g.Sum(h => h.Cost!.Value),
                CostByCategory = g.GroupBy(h => h.EventType)
                    .Select(cg => new HouseCategoryCostModel { EventType = cg.Key, Cost = cg.Sum(h => h.Cost!.Value) })
                    .OrderBy(c => c.EventType)
                    .ToList()
            })
            .ToList();
}
