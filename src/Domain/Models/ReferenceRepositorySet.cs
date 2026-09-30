using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The six owner-less reference repositories as one value, for the operations that genuinely span all of them
/// (today <c>ReferenceDataImportService</c>, whose whole point is importing every collection in one pass with
/// people resolved first).
/// <para>
/// They share no base interface on purpose - each is purpose-built for its collection, and none of them fits
/// <c>IDataRepository&lt;T&gt;</c>'s owner-scoped CRUD - so passing them individually is what pushed that
/// signature past Sonar's parameter limit. Same fix as <see cref="OwnedItemImportAdapter{TModel,TRequestItem}"/>:
/// bundle the values, don't change the design.
/// </para>
/// </summary>
public record ReferenceRepositorySet(
    ITvShowReferenceRepository TvShows,
    IMovieReferenceRepository Movies,
    IPersonReferenceRepository People,
    IBookReferenceRepository Books,
    IVideoGameReferenceRepository VideoGames,
    IAlbumReferenceRepository Albums);
