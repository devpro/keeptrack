namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Which trackable item type an Amazon order-history row should be imported as - picked per row in the
/// review UI, since Amazon's export has no category column to detect this automatically.
/// </summary>
public enum AmazonImportMediaType
{
    Book,
    Movie,
    TvShow,
    VideoGame
}
