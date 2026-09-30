using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Builds a recipient's own copy of a shared media item, carrying only its identity and reference link -
/// title, creator, year and <c>ReferenceId</c>. Everything personal to the sharer (rating, notes,
/// favorite/wishlist flags, owned copies, watched/read dates) is deliberately dropped: the recipient is
/// starting their own record, not inheriting the sharer's opinions or possessions. Keeping
/// <c>ReferenceId</c> means the copy is instantly cover-art/synopsis-linked, since reference data is
/// shared and owner-less. Personal categories (car/house/health) are never copyable, so they have no
/// method here - see <see cref="ShareCategoryClassifier"/>.
/// </summary>
public static class SharedItemCopyService
{
    public static MovieModel CopyMovie(MovieModel source, string ownerId) => new()
    {
        OwnerId = ownerId,
        Title = source.Title,
        Year = source.Year,
        ReferenceId = source.ReferenceId
    };

    public static TvShowModel CopyTvShow(TvShowModel source, string ownerId) => new()
    {
        OwnerId = ownerId,
        Title = source.Title,
        Year = source.Year,
        ReferenceId = source.ReferenceId
    };

    public static BookModel CopyBook(BookModel source, string ownerId) => new()
    {
        OwnerId = ownerId,
        Title = source.Title,
        Author = source.Author,
        Year = source.Year,
        ReferenceId = source.ReferenceId
    };

    public static AlbumModel CopyAlbum(AlbumModel source, string ownerId) => new()
    {
        OwnerId = ownerId,
        Title = source.Title,
        Artist = source.Artist,
        Year = source.Year,
        ReferenceId = source.ReferenceId
    };

    public static VideoGameModel CopyVideoGame(VideoGameModel source, string ownerId) => new()
    {
        OwnerId = ownerId,
        Title = source.Title,
        Year = source.Year,
        ReferenceId = source.ReferenceId
    };
}
