using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The repositories of the six owned-item types as one value, for an import spanning all of them, as <see cref="ReferenceRepositorySet"/> is for the reference collections.
/// </summary>
public record OwnedItemRepositorySet(
    IBookRepository Books,
    IMovieRepository Movies,
    ITvShowRepository TvShows,
    IVideoGameRepository VideoGames,
    IGearRepository Gear,
    ICollectibleRepository Collectibles);
