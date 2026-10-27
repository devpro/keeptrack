using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ITvShowRepository : IDataRepository<TvShowModel>, IExploreSourceRepository
{
    /// <summary>
    /// Sets <see cref="TvShowModel.ReferenceId"/>
    /// and <see cref="TvShowModel.Title"/> to the reference's values on the records <paramref name="target"/> names (see <see cref="ReferenceLinkTarget"/>).
    /// It also sets <see cref="TvShowModel.Year"/> when the reference has one, so a linked show starts with a trustworthy year, still editable.
    /// The tenant's own rating, notes and episodes are never touched.
    /// </summary>
    Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Copies the rating again onto every show linked to <paramref name="referenceId"/> (see <see cref="IMovieRepository.SetReferenceRatingAsync"/>).
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
    /// Distinct (title, year) pairs across every tenant's unlinked shows, for the admin queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();

    /// <summary>
    /// Every tenant's linked shows marked <see cref="TvShowStatus.Finished"/>, which the sync re-checks against their refreshed episode guide.
    /// Not owner-scoped, since a background pass drives it, not an owner's request.
    /// Only finished shows are returned, never <see cref="TvShowStatus.Stopped"/> or unset ones,
    /// which the tenant stopped tracking on purpose, so a new season does not reopen them.
    /// </summary>
    Task<IReadOnlyList<TvShowModel>> FindFinishedLinkedShowsAsync();
}
