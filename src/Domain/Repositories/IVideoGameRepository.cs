using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IVideoGameRepository : IDataRepository<VideoGameModel>, IExploreSourceRepository
{
    /// <summary>
    /// Sets <see cref="VideoGameModel.ReferenceId"/>, <see cref="VideoGameModel.Title"/> and <see cref="VideoGameModel.Year"/> to the reference's values on the records <paramref name="target"/> names (see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>).
    /// </summary>
    Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Copies the rating again onto every game linked to <paramref name="referenceId"/> (see <see cref="IMovieRepository.SetReferenceRatingAsync"/>).
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// <see cref="SetReferenceRatingAsync"/> for a batch, as one bulk write (see <see cref="IMovieRepository.SetReferenceRatingsAsync"/>).
    /// </summary>
    Task<long> SetReferenceRatingsAsync(IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)> updates);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/>, an unstamped item included.
    /// The admin recompute skips its whole pass when this is zero, rather than rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Moves every tenant's game linked to <paramref name="fromReferenceId"/> onto <paramref name="toReferenceId"/>, returning how many moved.
    /// The admin merge of two reference documents describing one work deletes the absorbed one, and an item still pointing at it would silently lose its cover, rating and Explore exclusion.
    /// <para>
    /// Across every tenant by design, since a reference is shared, so repairing it repairs it for everyone who linked it.
    /// The controller makes it admin only.
    /// </para>
    /// </summary>
    Task<long> RepointReferenceAsync(string fromReferenceId, string toReferenceId);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's unlinked games, for the admin queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
