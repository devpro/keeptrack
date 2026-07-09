namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// House history event type. Kept as a separate definition from <c>Keeptrack.Domain.Models.HouseEventType</c>
/// since WebApi.Contracts doesn't depend on Domain - member names must stay identical so AutoMapper can map
/// enum-to-enum by name.
/// </summary>
public enum HouseEventType
{
    Maintenance,
    Installation,
    Rework,
    Purchase,
    Bill,
    Other
}
