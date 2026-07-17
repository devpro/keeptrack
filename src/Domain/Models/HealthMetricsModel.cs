using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Computed metrics for one health profile - see <see cref="Services.HealthMetricsService"/>.
/// </summary>
public class HealthMetricsModel
{
    public required List<HealthCostHistoryPointModel> CostHistory { get; set; }

    public required List<HealthLastVisitModel> LastVisits { get; set; }

    public required List<HealthUnbalancedRecordModel> UnbalancedRecords { get; set; }
}

/// <summary>
/// One year of health spending: what was paid, what came back, what it really cost.
/// </summary>
public class HealthCostHistoryPointModel
{
    public required int Year { get; set; }

    public required double TotalPaid { get; set; }

    public required double TotalReimbursed { get; set; }

    /// <summary>What the year really cost after every reimbursement: paid minus reimbursed.</summary>
    public required double OutOfPocket { get; set; }
}

/// <summary>
/// "When did I last see this kind of doctor" - one line per specialty seen in appointments, nothing more
/// (no names, no counts - owner's explicit display choice).
/// </summary>
public class HealthLastVisitModel
{
    public required string Specialty { get; set; }

    public required DateTime LastVisitDate { get; set; }
}

/// <summary>
/// A paid record whose money doesn't balance: price - public - insurance - leftover isn't zero.
/// Positive <see cref="MissingAmount"/> = money still expected (chase the mutuelle, check the bank
/// account); negative = more was received than the price accounts for, worth a look too. A record with
/// nothing entered yet is simply missing its full price - the same list covers "not started" and
/// "partially settled" alike.
/// </summary>
public class HealthUnbalancedRecordModel
{
    public required string RecordId { get; set; }

    public required DateTime HistoryDate { get; set; }

    /// <summary>Whatever identifies the record best: practitioner, else description, else specialty.</summary>
    public required string Label { get; set; }

    public required double Price { get; set; }

    public required double MissingAmount { get; set; }
}
