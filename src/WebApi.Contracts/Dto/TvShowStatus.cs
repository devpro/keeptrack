namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Mirrors <c>Keeptrack.Domain.Models.TvShowStatus</c> - WebApi.Contracts can't depend on Domain, so this
/// is a separate enum with matching member names; the generated Mapperly mapper (<c>EnumMappingStrategy.ByName</c>)
/// maps enum-to-enum by name.
/// </summary>
public enum TvShowStatus
{
    Current,
    Finished,
    Stopped
}
