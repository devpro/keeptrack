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
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalArtist = null, string? canonicalGenre = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Re-propagates the denormalized <see cref="AlbumModel.ReferenceRating"/>/<see cref="AlbumModel.ReferenceRatingScale"/>
    /// to every tenant album already linked to <paramref name="referenceId"/> - see <see cref="IMovieRepository.SetReferenceRatingAsync"/>.
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/> (an item
    /// stamped with none at all counts). Lets the admin "recompute" action skip its whole pass when every item
    /// is already on the selected source, instead of rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's albums that have no <see cref="AlbumModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
