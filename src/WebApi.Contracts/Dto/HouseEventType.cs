namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// House history event type.
/// A copy of the Domain enum, since Contracts does not depend on Domain, mapped by name, so member names stay identical.
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
