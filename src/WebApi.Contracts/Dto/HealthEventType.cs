namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// What kind of health-journal entry a record is.
/// A copy of the Domain enum, mapped by name, so member names stay identical (see docs/data-model.md).
/// </summary>
public enum HealthEventType
{
    Appointment,
    Sickness,
    Other
}
