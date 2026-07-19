using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Pure, stateless computation over a house's history - no persistence of its own, same shape as <see cref="CarMetricsService"/>/<see cref="WatchNextService"/>.
/// Deliberately limited to a yearly cost breakdown plus a last-record-per-type readout: House has no
/// reminders/due-date engine by design - the owner tracks recurring bills/maintenance elsewhere and only
/// wants an exhaustive record plus a yearly cost review here.
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
    /// "When did I last log each kind of house event" - one line per <see cref="HouseEventType"/>, most
    /// recent first. Same shape as <see cref="CarMetricsService"/>'s own ComputeLastRecords.
    /// </summary>
    private static List<HouseLastRecordModel> ComputeLastRecords(IEnumerable<HouseHistoryModel> history) =>
        history
            .GroupBy(h => h.EventType)
            .Select(g => new HouseLastRecordModel { EventType = g.Key, LastDate = g.Max(h => h.HistoryDate) })
            .OrderByDescending(r => r.LastDate)
            .ToList();
}
