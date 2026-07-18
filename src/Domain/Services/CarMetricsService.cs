using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes fuel/electric consumption, cost history, mileage-consistency warnings and a last-record-per-type readout from a car's full intervention history.
/// Pure computation over an in-memory list, same shape as WatchNextService - nothing here is persisted, so a car's metrics are always derived fresh from its history.
/// </summary>
public static class CarMetricsService
{
    private const double MileageToleranceKm = 1;

    public static CarMetricsModel ComputeMetrics(IEnumerable<CarHistoryModel> history)
    {
        var historyList = history.ToList();

        return new CarMetricsModel
        {
            FuelConsumption = ComputeConsumption(historyList, h => h.FuelVolume, out var averageFuel),
            AverageFuelConsumptionPer100Km = averageFuel,
            ElectricConsumption = ComputeConsumption(historyList, h => h.ElectricVolume, out var averageElectric),
            AverageElectricConsumptionPer100Km = averageElectric,
            CostHistory = ComputeCostHistory(historyList),
            TotalCost = historyList.Sum(h => h.Cost ?? 0),
            MileageWarnings = ComputeMileageWarnings(historyList),
            LastRecords = ComputeLastRecords(historyList)
        };
    }

    /// <summary>
    /// Shared trip-computer algorithm for both fuel (liters) and electric (kWh) consumption - a data point is
    /// only ever emitted across a full refill/recharge (<see cref="CarHistoryModel.IsFullRefill"/>): the
    /// quantity added by every refill since the last full one is accumulated, and once a full refill closes
    /// that window, the accumulated quantity is divided by the mileage covered since the previous full refill.
    /// A partial refill on its own never produces a data point.
    /// </summary>
    private static List<ConsumptionPointModel> ComputeConsumption(
        IReadOnlyList<CarHistoryModel> history, Func<CarHistoryModel, double?> quantitySelector, out double? average)
    {
        var refuels = history
            .Where(h => h.EventType == CarHistoryType.Refuel && h.Mileage is not null && quantitySelector(h) is not null)
            .OrderBy(h => h.Mileage)
            .ToList();

        var points = new List<ConsumptionPointModel>();
        var quantitySinceLastFullRefill = 0.0;
        CarHistoryModel? lastFullRefill = null;

        foreach (var refuel in refuels)
        {
            quantitySinceLastFullRefill += quantitySelector(refuel)!.Value;

            if (refuel.IsFullRefill != true) continue;

            if (lastFullRefill is not null)
            {
                var distance = refuel.Mileage!.Value - lastFullRefill.Mileage!.Value;
                if (distance > 0)
                {
                    points.Add(new ConsumptionPointModel
                    {
                        Date = DateOnly.FromDateTime(refuel.HistoryDate),
                        ValuePer100Km = quantitySinceLastFullRefill / distance * 100
                    });
                }
            }

            lastFullRefill = refuel;
            quantitySinceLastFullRefill = 0;
        }

        average = points.Count > 0 ? points.Average(p => p.ValuePer100Km) : null;
        return points;
    }

    private static List<CarCostHistoryPointModel> ComputeCostHistory(IReadOnlyList<CarHistoryModel> history) =>
        history
            .Where(h => h.Cost is not null)
            .GroupBy(h => new DateOnly(h.HistoryDate.Year, h.HistoryDate.Month, 1))
            .OrderBy(g => g.Key)
            .Select(g => new CarCostHistoryPointModel
            {
                Period = g.Key,
                FuelCost = g.Where(h => h.EventType == CarHistoryType.Refuel).Sum(h => h.Cost!.Value),
                MaintenanceCost = g.Where(h => h.EventType != CarHistoryType.Refuel).Sum(h => h.Cost!.Value)
            })
            .ToList();

    /// <summary>
    /// The automated version of the manual Excel cross-check the user used to do by hand: a regression check
    /// (the odometer can never go backwards) plus a delta cross-check between the user-entered
    /// <see cref="CarHistoryModel.DeltaMileage"/> (typically read off the car's trip computer at refuel time)
    /// and the computed mileage difference between consecutive entries. A mismatch means either number was
    /// mistyped, or - if the computed delta is larger than the entered one - an entry was never logged at all.
    /// Advisory only: nothing here excludes an entry from the metrics above or corrects it automatically.
    /// </summary>
    private static List<CarMileageWarningModel> ComputeMileageWarnings(IReadOnlyList<CarHistoryModel> history)
    {
        var ordered = history
            .Where(h => h.Mileage is not null)
            .OrderBy(h => h.HistoryDate)
            .ToList();

        var warnings = new List<CarMileageWarningModel>();

        for (var i = 1; i < ordered.Count; i++)
        {
            var previous = ordered[i - 1];
            var current = ordered[i];

            if (current.Mileage < previous.Mileage)
            {
                warnings.Add(new CarMileageWarningModel
                {
                    CarHistoryId = current.Id!,
                    Message = $"Mileage {current.Mileage} on {current.HistoryDate:yyyy-MM-dd} is lower than {previous.Mileage} " +
                              $"recorded on {previous.HistoryDate:yyyy-MM-dd}."
                });
                continue;
            }

            if (current.DeltaMileage is null) continue;

            var computedDelta = current.Mileage!.Value - previous.Mileage!.Value;
            if (Math.Abs(computedDelta - current.DeltaMileage.Value) <= MileageToleranceKm) continue;

            var suggestsMissingEntry = computedDelta > current.DeltaMileage.Value;
            warnings.Add(new CarMileageWarningModel
            {
                CarHistoryId = current.Id!,
                Message = $"Entered delta mileage ({current.DeltaMileage}) doesn't match the {computedDelta} " +
                          $"difference between this entry's mileage ({current.Mileage}) and the previous entry's " +
                          $"({previous.Mileage} on {previous.HistoryDate:yyyy-MM-dd})." +
                          (suggestsMissingEntry ? " An entry may be missing in between." : " Check both entries for a typo.")
            });
        }

        return warnings;
    }

    /// <summary>
    /// "When did I last log each kind of event" - one line per <see cref="CarHistoryType"/>, most recent
    /// first. Same shape as HealthMetricsService.ComputeLastVisits, simpler (an enum key needs no
    /// whitespace/Trim() handling a free-text specialty does).
    /// </summary>
    private static List<CarLastRecordModel> ComputeLastRecords(IReadOnlyList<CarHistoryModel> history) =>
        history
            .GroupBy(h => h.EventType)
            .Select(g => new CarLastRecordModel { EventType = g.Key, LastDate = g.Max(h => h.HistoryDate) })
            .OrderByDescending(r => r.LastDate)
            .ToList();
}
