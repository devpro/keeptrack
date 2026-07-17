namespace Keeptrack.Domain.Models;

/// <summary>
/// What kind of health-journal entry a <see cref="HealthRecordModel"/> is - a real discriminated enum
/// (never a bare free-text "type"), same rule as <see cref="CarHistoryType"/>/<see cref="HouseEventType"/>.
/// Appointment carries the specialty/practitioner/price/reimbursement fields; Sickness is "I was sick,
/// here's why" with no money attached; Other covers everything else (vaccination, test results, ...).
/// </summary>
public enum HealthEventType
{
    Appointment,
    Sickness,
    Other
}
