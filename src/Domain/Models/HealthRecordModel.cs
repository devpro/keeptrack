using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One health journal entry (an appointment, a sickness, anything else dated) of a <see cref="HealthProfileModel"/>.
/// A separate collection referencing its parent by id, since it grows without bound over the years (see docs/data-model.md's "Child entities" section).
/// <see cref="HistoryDate"/> is a full <see cref="DateTime"/> like Car's, not a DateOnly like House's, since an appointment's time of day is real information.
/// </summary>
public class HealthRecordModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string HealthProfileId { get; set; }

    public required DateTime HistoryDate { get; set; }

    public required HealthEventType EventType { get; set; }

    /// <summary>Medical specialty ("généraliste", "dentiste", "dermatologue"), free text.</summary>
    public string? Specialty { get; set; }

    /// <summary>The practitioner's name.</summary>
    public string? Practitioner { get; set; }

    public string? Description { get; set; }

    public string? Notes { get; set; }

    /// <summary>What was paid at the time, before any reimbursement.</summary>
    public double? Price { get; set; }

    /// <summary>Reimbursement from the public health system (assurance maladie), filled in later.</summary>
    public double? PublicReimbursement { get; set; }

    /// <summary>Reimbursement from the complementary insurer (mutuelle), filled in later.</summary>
    public double? InsuranceReimbursement { get; set; }

    /// <summary>
    /// The accepted remainder (reste à charge): the part of the price nobody will reimburse.
    /// Recording it lets the balance close: a record is settled exactly when price minus public, insurance and not covered is zero.
    /// Anything else is flagged for the owner to chase (see <see cref="Services.HealthMetricsService"/>).
    /// </summary>
    public double? NotCovered { get; set; }
}
