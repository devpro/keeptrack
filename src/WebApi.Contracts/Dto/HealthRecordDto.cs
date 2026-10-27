using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One health-journal entry: an appointment, a sickness, or any other dated health event.
/// </summary>
public class HealthRecordDto : IHasId
{
    /// <summary>
    /// Record ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Health profile ID (whose journal this entry belongs to).
    /// </summary>
    public required string HealthProfileId { get; set; }

    /// <summary>
    /// When it happened, with the time of day an appointment has.
    /// </summary>
    public required DateTime HistoryDate { get; set; }

    /// <summary>
    /// Event type (Appointment, Sickness, Other).
    /// </summary>
    public required HealthEventType EventType { get; set; }

    /// <summary>
    /// Medical specialty of an appointment ("généraliste", "dentiste").
    /// </summary>
    public string? Specialty { get; set; }

    /// <summary>
    /// The practitioner's name.
    /// </summary>
    public string? Practitioner { get; set; }

    /// <summary>
    /// Free-text description: the reason for the visit, the sickness.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Free-text notes: outcome, prescriptions, follow-up.
    /// </summary>
    public string? Notes { get; set; }

    /// <summary>
    /// What was paid at the time, before any reimbursement.
    /// </summary>
    public double? Price { get; set; }

    /// <summary>
    /// Reimbursement from the public health system (assurance maladie), usually filled in later.
    /// </summary>
    public double? PublicReimbursement { get; set; }

    /// <summary>
    /// Reimbursement from the complementary insurer (mutuelle), usually filled in later.
    /// </summary>
    public double? InsuranceReimbursement { get; set; }

    /// <summary>
    /// The accepted remainder (reste à charge) nobody will reimburse.
    /// A record is settled exactly when price minus public, insurance and not covered is zero.
    /// Anything else appears in the metrics' to-check list with the missing amount.
    /// </summary>
    public double? NotCovered { get; set; }
}
