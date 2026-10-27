namespace Keeptrack.Domain.Models;

/// <summary>
/// The kind of a <see cref="HealthRecordModel"/>, an enum like <see cref="CarHistoryType"/> and <see cref="HouseEventType"/> rather than free text.
/// An appointment carries the specialty, practitioner, price and reimbursement fields.
/// A sickness records being ill and why, with no money attached.
/// Other covers everything else (vaccinations, test results).
/// </summary>
public enum HealthEventType
{
    Appointment,
    Sickness,
    Other
}
