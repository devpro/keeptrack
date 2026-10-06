using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Builds the recipient's own copy of a shared media item, with only its identity and reference link: title, creator, year and <c>ReferenceId</c>.
/// What is personal to the sharer (rating, notes, flags, owned copies, watched or read dates) is dropped, since the recipient starts their own record.
/// Keeping <c>ReferenceId</c> links the copy at once to its cover and synopsis, since reference data is shared.
/// Other categories are never copyable (see <see cref="ShareCategoryClassifier"/>), so they have no method here.
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
