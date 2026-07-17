using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one health profile: yearly costs after reimbursements, last visit per
/// practitioner, and paid records still waiting on a reimbursement.
/// </summary>
public class HealthMetricsDto
{
    /// <summary>
    /// Health spending by year.
    /// </summary>
    public required List<HealthCostHistoryPointDto> CostHistory { get; set; }

    /// <summary>
    /// When each practitioner was last seen, most recent first.
    /// </summary>
    public required List<HealthLastVisitDto> LastVisits { get; set; }

    /// <summary>
    /// Paid records whose money doesn't balance to zero (price - public - insurance - leftover), oldest
    /// first - money is still expected, or more arrived than the price accounts for.
    /// </summary>
    public required List<HealthUnbalancedRecordDto> UnbalancedRecords { get; set; }
}

/// <summary>
/// One year of health spending.
/// </summary>
public class HealthCostHistoryPointDto
{
    /// <summary>
    /// Year.
    /// </summary>
    public required int Year { get; set; }

    /// <summary>
    /// Total paid over the year, before reimbursements.
    /// </summary>
    public required double TotalPaid { get; set; }

    /// <summary>
    /// Total reimbursed over the year (public + insurance).
    /// </summary>
    public required double TotalReimbursed { get; set; }

    /// <summary>
    /// What the year really cost: paid minus reimbursed.
    /// </summary>
    public required double OutOfPocket { get; set; }
}

/// <summary>
/// When a practitioner was last seen.
/// </summary>
public class HealthLastVisitDto
{
    /// <summary>
    /// The practitioner's name.
    /// </summary>
    public required string Practitioner { get; set; }

    /// <summary>
    /// The practitioner's specialty, when recorded.
    /// </summary>
    public string? Specialty { get; set; }

    /// <summary>
    /// The most recent appointment date.
    /// </summary>
    public required DateTime LastVisitDate { get; set; }

    /// <summary>
    /// How many appointments are recorded with this practitioner.
    /// </summary>
    public required int VisitCount { get; set; }
}

/// <summary>
/// A paid record whose money doesn't balance to zero.
/// </summary>
public class HealthUnbalancedRecordDto
{
    /// <summary>
    /// The record's id.
    /// </summary>
    public required string RecordId { get; set; }

    /// <summary>
    /// When the expense happened.
    /// </summary>
    public required DateTime HistoryDate { get; set; }

    /// <summary>
    /// Practitioner, description or specialty - whatever identifies the record best.
    /// </summary>
    public required string Label { get; set; }

    /// <summary>
    /// The amount paid.
    /// </summary>
    public required double Price { get; set; }

    /// <summary>
    /// Price minus reimbursements minus leftover: positive = money still expected, negative = more was
    /// received than the price accounts for.
    /// </summary>
    public required double MissingAmount { get; set; }
}
