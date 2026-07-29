using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ITvShowRepository : IDataRepository<TvShowModel>
{
    /// <summary>
    /// Sets <see cref="TvShowModel.ReferenceId"/> and <see cref="TvShowModel.Title"/> (to the reference's
    /// canonical name) on every tenant's show matching this title/year that doesn't already have a
    /// reference link - the confirmed cross-tenant propagation for reference-data linking. Also sets
    /// <see cref="TvShowModel.Year"/> to <paramref name="canonicalYear"/> when the reference has one, so a
    /// newly-linked show starts with a trustworthy year instead of whatever the tenant originally guessed
    /// (still freely editable afterward). Otherwise never touches any tenant's own rating/notes/episodes.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null);

    /// <summary>
    /// Re-propagates the denormalized <see cref="TvShowModel.ReferenceRating"/>/<see cref="TvShowModel.ReferenceRatingScale"/>
    /// to every tenant show already linked to <paramref name="referenceId"/> - see <see cref="IMovieRepository.SetReferenceRatingAsync"/>.
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's shows that have no <see cref="TvShowModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();

    /// <summary>
    /// Every tenant's shows marked <see cref="TvShowStatus.Finished"/> that carry a reference link - the
    /// candidates the periodic finished-show status reconciliation re-checks against their (freshly synced)
    /// reference episode guide. Cross-tenant and unscoped, like <see cref="SetReferenceLinkAsync"/>: it's
    /// driven by a background pass, not an owner request. Only <c>Finished</c> shows are returned, never
    /// <see cref="TvShowStatus.Stopped"/> or an unset status - those mean the tenant has deliberately stopped
    /// tracking, so a new season must not reopen them.
    /// </summary>
    Task<IReadOnlyList<TvShowModel>> FindFinishedLinkedShowsAsync();
}
