namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Which trackable item type a generic import row should be created/merged as.
/// Read per row from an optional "Type" column when the file has one, otherwise picked in the review UI.
/// A copy of the Domain enum, mapped by name, so member names stay identical.
/// </summary>
public enum ImportMediaType
{
    Book,
    Movie,
    TvShow,
    VideoGame,
    Gear,
    Collectible
}
