namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Which trackable type an Amazon order row is imported as, picked per row in the review UI, since the export has no category column.
/// </summary>
public enum AmazonImportMediaType
{
    Book,
    Movie,
    TvShow,
    VideoGame,
    Gear,
    Collectible
}
