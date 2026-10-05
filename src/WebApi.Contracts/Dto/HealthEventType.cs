namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// What kind of health-journal entry a record is. Member names must stay identical to the Domain enum
/// (mapped ByName - see docs/data-model.md's enum convention).
/// </summary>
public enum HealthEventType
{
    Appointment,
    Sickness,
    Other
}
