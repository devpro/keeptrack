namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Type of property (house, apartment, or other).
/// A copy of the Domain enum, since Contracts does not depend on Domain, mapped by name, so member names stay identical.
/// </summary>
public enum PropertyType
{
    House,
    Apartment,
    Other
}
