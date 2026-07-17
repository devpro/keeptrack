using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One health-journal entry (an appointment, a sickness, anything else dated), owned by a
/// <see cref="HealthProfileModel"/> - a separate top-level collection referencing its parent by id, same
/// deliberate schema choice as CarHistory/Episode (unbounded per-parent growth over years; see CLAUDE.md's
/// "Child entities" section). <see cref="HistoryDate"/> is a full <see cref="DateTime"/> (Car's pattern,
/// not House's DateOnly): an appointment's time of day is real information ("was I there at 9:00 or 17:30").
/// </summary>
public class HealthRecordModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string HealthProfileId { get; set; }

    public required DateTime HistoryDate { get; set; }

    public required HealthEventType EventType { get; set; }

    /// <summary>Medical specialty ("généraliste", "dentiste", "dermatologue", ...) - free text.</summary>
    public string? Specialty { get; set; }

    /// <summary>The practitioner's name - what "when did I last see Dr X" is answered from.</summary>
    public string? Practitioner { get; set; }

    public string? Description { get; set; }

    public string? Notes { get; set; }

    /// <summary>What was paid at the time, before any reimbursement.</summary>
    public double? Price { get; set; }

    /// <summary>Reimbursement from the public health system (assurance maladie), filled in later.</summary>
    public double? PublicReimbursement { get; set; }

    /// <summary>Reimbursement from the private/complementary insurer (mutuelle), filled in later.</summary>
    public double? InsuranceReimbursement { get; set; }

    /// <summary>
    /// The accepted remainder (reste à charge): the part of the price no one will ever reimburse.
    /// Recording it is what lets the balance check close: a record is settled exactly when
    /// price - public - insurance - leftover == 0, and anything else is flagged for the owner to chase
    /// (see <see cref="Services.HealthMetricsService"/>).
    /// </summary>
    public double? NotCovered { get; set; }
}
