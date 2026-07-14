using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IAlbumRepository : IDataRepository<AlbumModel>
{
    /// <summary>
    /// Sets <see cref="AlbumModel.ReferenceId"/>, <see cref="AlbumModel.Title"/>, <see cref="AlbumModel.Year"/>,
    /// <see cref="AlbumModel.Artist"/> and <see cref="AlbumModel.Genre"/> (to the reference's canonical values)
    /// on every tenant's album matching this title/year that doesn't already have a reference link - see
    /// <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalArtist = null, string? canonicalGenre = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's albums that have no <see cref="AlbumModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync();
}
