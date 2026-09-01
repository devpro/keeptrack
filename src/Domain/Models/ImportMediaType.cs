namespace Keeptrack.Domain.Models;

/// <summary>
/// Which trackable item type a generic import row should be created/merged as. The Domain-side counterpart of
/// the <c>ImportMediaType</c> DTO enum (member names kept identical, mapped by name) - the generic importer
/// reads it per row from an optional "Type" column, falling back to a per-row picker in the review UI when a
/// row's Type is blank or unrecognized.
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
