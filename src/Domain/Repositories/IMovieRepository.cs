using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IMovieRepository : IDataRepository<MovieModel>, IExploreSourceRepository
{
    /// <summary>
    /// Sets <see cref="MovieModel.ReferenceId"/>, <see cref="MovieModel.Title"/>, <see cref="MovieModel.Year"/>
    /// and the rating copy to the reference's values on the records <paramref name="target"/> names (see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>).
    /// </summary>
    Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Copies the rating again onto every movie linked to <paramref name="referenceId"/>, keeping the copies current after a refresh.
    /// Unlike <see cref="SetReferenceLinkAsync"/>, it matches by reference id, so it reaches every linked item of every tenant.
    /// Null clears a rating that went away.
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// <see cref="SetReferenceRatingAsync"/> for a batch of references, as one bulk write, for the admin recompute of a whole domain.
    /// Each entry still updates all of its reference's linked items server side, so the work grows with the user base but the round trips do not.
    /// Returns the number of tenant items modified.
    /// </summary>
    Task<long> SetReferenceRatingsAsync(IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)> updates);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/>, an unstamped item included.
    /// The admin recompute skips its whole pass when this is zero, rather than rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's unlinked movies, for the admin queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
