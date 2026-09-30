namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Which trackable item type a generic import row should be created/merged as. Read per row from an optional
/// "Type" column when the file has one, otherwise picked in the review UI. Member names are kept identical to
/// the Domain <c>ImportMediaType</c> enum so the mapper can map them by name.
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
