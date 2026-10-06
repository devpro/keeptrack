using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Pure computation over a house's history, like <see cref="CarMetricsService"/>.
/// Limited to a yearly cost breakdown and the last record per type, with no reminders or due dates (owner's call):
/// recurring bills are tracked elsewhere, and this is an exhaustive record with a yearly cost review.
/// </summary>
public static class HouseMetricsService
{
    public static HouseMetricsModel ComputeMetrics(IEnumerable<HouseHistoryModel> history)
    {
        var list = history.ToList();
        return new HouseMetricsModel { CostHistory = ComputeAnnualCostHistory(list), LastRecords = ComputeLastRecords(list) };
    }

    private static List<HouseCostHistoryPointModel> ComputeAnnualCostHistory(IEnumerable<HouseHistoryModel> history)
    {
        return history
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

    /// <summary>
    /// When each kind of house event was last logged, one line per <see cref="HouseEventType"/>, most recent first.
    /// </summary>
    private static List<HouseLastRecordModel> ComputeLastRecords(IEnumerable<HouseHistoryModel> history) =>
        history
            .GroupBy(h => h.EventType)
            .Select(g => new HouseLastRecordModel { EventType = g.Key, LastDate = g.Max(h => h.HistoryDate) })
            .OrderByDescending(r => r.LastDate)
            .ToList();
}
