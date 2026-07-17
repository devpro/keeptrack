namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Type of property (house, apartment, or other). Kept as a separate definition from
/// <c>Keeptrack.Domain.Models.PropertyType</c> since WebApi.Contracts doesn't depend on Domain - member
/// names must stay identical so the generated Mapperly mapper (<c>EnumMappingStrategy.ByName</c>) can
/// map enum-to-enum by name.
/// </summary>
public enum PropertyType
{
    House,
    Apartment,
    Other
}
