using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IAlbumRepository : IDataRepository<AlbumModel>
{
    /// <summary>
    /// Sets <see cref="AlbumModel.ReferenceId"/>, <see cref="AlbumModel.Title"/>, <see cref="AlbumModel.Year"/>, <see cref="AlbumModel.Artist"/>
    /// and <see cref="AlbumModel.Genre"/> to the reference's values on the records <paramref name="target"/> names (see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>).
    /// An admin's match also requires the artist it names.
    /// </summary>
    Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalArtist = null, string? canonicalGenre = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Copies the rating again onto every album linked to <paramref name="referenceId"/> (see <see cref="IMovieRepository.SetReferenceRatingAsync"/>).
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/>, an unstamped item included.
    /// The admin recompute skips its whole pass when this is zero, rather than rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Distinct (title, year, artist) combinations across every tenant's unlinked albums, for the admin queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
