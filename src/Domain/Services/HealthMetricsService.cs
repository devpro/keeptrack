using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Pure computation over a health profile's journal, like <see cref="HouseMetricsService"/> and <see cref="CarMetricsService"/>.
/// It answers three questions the journal does not show at a glance: what health costs per year after reimbursements,
/// when each specialty was last seen, and which paid records still wait on a reimbursement.
/// </summary>
public static class HealthMetricsService
{
    /// <summary>
    /// Two amounts closer than this are equal, since reimbursement arithmetic runs on doubles and a rounding residue must never flag a settled record.
    /// </summary>
    private const double BalanceTolerance = 0.05;

    public static HealthMetricsModel ComputeMetrics(IEnumerable<HealthRecordModel> records)
    {
        var list = records.ToList();
        return new HealthMetricsModel { CostHistory = ComputeAnnualCostHistory(list), LastVisits = ComputeLastVisits(list), UnbalancedRecords = ComputeUnbalancedRecords(list) };
    }

    /// <summary>
    /// What is still missing once everything entered is counted: the price minus both reimbursements and the accepted not-covered part (reste à charge).
    /// Zero means settled.
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
    /// One line per specialty across every appointment, most recently seen first, so the last dentist visit is read at a glance.
    /// Grouped by specialty rather than practitioner (owner's call): the question is the kind of care, and the journal carries the names.
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
    /// Every paid record whose money does not balance, oldest first, since the longest-waiting claim is the one to chase.
    /// Partial settlements are flagged too: a record with only the public reimbursement entered is exactly the "did the mutuelle pay?" case.
    /// A negative missing amount, more received than the price, is just as worth a look.
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
