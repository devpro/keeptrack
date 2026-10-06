namespace Keeptrack.Domain.Models;

/// <summary>
/// Which trackable type an import row is created or merged as.
/// The generic importer reads it per row from an optional "Type" column, and the review UI asks for it when the column is blank or unrecognized.
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
