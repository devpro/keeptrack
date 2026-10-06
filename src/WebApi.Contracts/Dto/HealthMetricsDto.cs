using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one health profile: yearly costs after reimbursements, the last visit per specialty, and paid records still waiting on a reimbursement.
/// </summary>
public class HealthMetricsDto
{
    /// <summary>
    /// Health spending by year.
    /// </summary>
    public required List<HealthCostHistoryPointDto> CostHistory { get; set; }

    /// <summary>
    /// When each specialty was last seen, most recent first.
    /// </summary>
    public required List<HealthLastVisitDto> LastVisits { get; set; }

    /// <summary>
    /// Paid records whose money does not balance (price minus public, insurance and not covered), oldest first.
    /// Money is still expected, or more arrived than the price accounts for.
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
/// When a specialty was last seen.
/// </summary>
public class HealthLastVisitDto
{
    /// <summary>
    /// The medical specialty.
    /// </summary>
    public required string Specialty { get; set; }

    /// <summary>
    /// The most recent appointment date for that specialty.
    /// </summary>
    public required DateTime LastVisitDate { get; set; }
}

/// <summary>
/// A paid record whose money does not balance.
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
    /// Practitioner, description or specialty, whichever identifies the record best.
    /// </summary>
    public required string Label { get; set; }

    /// <summary>
    /// The amount paid.
    /// </summary>
    public required double Price { get; set; }

    /// <summary>
    /// The price minus reimbursements and not covered: positive when money is still expected, negative when more was received than the price.
    /// </summary>
    public required double MissingAmount { get; set; }
}
