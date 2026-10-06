namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A copy of the Domain enum, since Contracts does not depend on Domain, mapped by name, so member names stay identical.
/// </summary>
public enum TvShowStatus
{
    Current,
    Finished,
    Stopped
}
