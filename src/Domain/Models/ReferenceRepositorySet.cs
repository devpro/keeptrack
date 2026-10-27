using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The six reference repositories as one value, for operations spanning all of them, such as <c>ReferenceDataImportService</c> importing every collection in one pass.
/// <para>
/// They share no base interface, since each is built for its collection and none fits <c>IDataRepository&lt;T&gt;</c>'s owner-scoped CRUD.
/// Bundling them keeps the signature within Sonar's parameter limit, as <see cref="OwnedItemImportAdapter{TModel,TRequestItem}"/> does.
/// </para>
/// </summary>
public record ReferenceRepositorySet(
    ITvShowReferenceRepository TvShows,
    IMovieReferenceRepository Movies,
    IPersonReferenceRepository People,
    IBookReferenceRepository Books,
    IVideoGameReferenceRepository VideoGames,
    IAlbumReferenceRepository Albums);
