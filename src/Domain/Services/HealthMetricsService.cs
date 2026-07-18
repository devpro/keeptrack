using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Pure, stateless computation over a health profile's journal -
/// no persistence of its own, same shape as <see cref="HouseMetricsService"/>/<see cref="CarMetricsService"/>.
/// Three views the raw journal can't answer at a glance:
/// what health costs per year after reimbursements, when each practitioner was last seen, and which paid records are still waiting on a reimbursement.
/// </summary>
public static class HealthMetricsService
{
    /// <summary>
    /// Two amounts closer than this are "equal" - reimbursement arithmetic runs on doubles, and a sub-cent residue must never flag a genuinely settled record.
    /// </summary>
    private const double BalanceTolerance = 0.05;

    public static HealthMetricsModel ComputeMetrics(IEnumerable<HealthRecordModel> records)
    {
        var list = records.ToList();
        return new HealthMetricsModel { CostHistory = ComputeAnnualCostHistory(list), LastVisits = ComputeLastVisits(list), UnbalancedRecords = ComputeUnbalancedRecords(list) };
    }

    /// <summary>
    /// What's still missing once everything entered is accounted for: price minus both reimbursements minus the accepted not-covered part (reste à charge).
    /// Zero = settled.
    /// </summary>
    private static double ComputeMissingAmount(HealthRecordModel record)
    {
        return (record.Price ?? 0) - (record.PublicReimbursement ?? 0) - (record.InsuranceReimbursement ?? 0) - (record.NotCovered ?? 0);
    }

    private static bool IsBalanced(HealthRecordModel record)
    {
        return Math.Abs(ComputeMissingAmount(record)) <= BalanceTolerance;
    }

    private static List<HealthCostHistoryPointModel> ComputeAnnualCostHistory(IEnumerable<HealthRecordModel> records)
    {
        return records
            .Where(r => r.Price is not null || r.PublicReimbursement is not null || r.InsuranceReimbursement is not null)
            .GroupBy(r => r.HistoryDate.Year)
            .OrderByDescending(g => g.Key)
            .Select(g =>
            {
                var paid = g.Sum(r => r.Price ?? 0);
                var reimbursed = g.Sum(r => (r.PublicReimbursement ?? 0) + (r.InsuranceReimbursement ?? 0));
                return new HealthCostHistoryPointModel { Year = g.Key, TotalPaid = paid, TotalReimbursed = reimbursed, OutOfPocket = paid - reimbursed };
            })
            .ToList();
    }

    /// <summary>
    /// One line per specialty across every appointment - most recently seen first, so "when did I last
    /// see a dentist" is the top of the list, not a search. Grouped by specialty rather than by
    /// practitioner name (owner's call): the question is about the kind of care, and the journal itself
    /// carries the names.
    /// </summary>
    private static List<HealthLastVisitModel> ComputeLastVisits(IEnumerable<HealthRecordModel> records)
    {
        return records
            .Where(r => r.EventType == HealthEventType.Appointment && !string.IsNullOrWhiteSpace(r.Specialty))
            .GroupBy(r => r.Specialty!.Trim())
            .Select(g => new HealthLastVisitModel { Specialty = g.Key, LastVisitDate = g.Max(r => r.HistoryDate) })
            .OrderByDescending(v => v.LastVisitDate)
            .ToList();
    }

    /// <summary>
    /// Every paid record whose money doesn't balance to zero, oldest first (the longest-waiting claim is
    /// the one to chase). This deliberately flags partial settlements too: a record with only the ameli
    /// payment entered is exactly the "did the mutuelle ever pay?" case the check exists for, and a
    /// negative missing amount (more received than the price accounts for) is just as worth a look.
    /// </summary>
    private static List<HealthUnbalancedRecordModel> ComputeUnbalancedRecords(IEnumerable<HealthRecordModel> records)
    {
        return records
            .Where(r => r.Price is > 0 && r.Id is not null && !IsBalanced(r))
            .OrderBy(r => r.HistoryDate)
            .Select(r => new HealthUnbalancedRecordModel
            {
                RecordId = r.Id!,
                HistoryDate = r.HistoryDate,
                Label = FirstNonEmpty(r.Practitioner, r.Description, r.Specialty) ?? r.EventType.ToString(),
                Price = r.Price!.Value,
                MissingAmount = ComputeMissingAmount(r)
            })
            .ToList();
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
    }
}
