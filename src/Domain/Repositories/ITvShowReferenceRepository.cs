using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared TV show reference collection.
/// Not an <see cref="IDataRepository{TModel}"/>, which with its MongoDB base class is constrained to owner-scoped paged CRUD and does not fit a shared lookup table.
/// </summary>
public interface ITvShowReferenceRepository
{
    Task<TvShowReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for list-page cover hydration: one query per page, never one per item.
    /// </summary>
    Task<List<TvShowReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The <paramref name="provider"/> id of each given reference, projected server side from <c>external_ids</c> alone.
    /// The Explore exclusion needs one string per reference, where <see cref="FindByIdsAsync"/> would fetch whole documents.
    /// </summary>
    Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider);

    /// <summary>
    /// One page of (id, ratings) for the admin rating recompute (see <see cref="IMovieReferenceRepository.FindRatingsAsync"/>).
    /// The projection matters most here, since a show's document embeds its whole episode guide.
    /// </summary>
    Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit);

    Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only fallback (normalized, any year), asked when the tenant has no year.
    /// It returns a match only when exactly one reference has this title, since ambiguous and not found mean the same to a caller that must not guess.
    /// </summary>
    Task<TvShowReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference by provider id (its TMDB id), the strongest sign of the same show, whatever its title.
    /// </summary>
    Task<TvShowReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<TvShowReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync refreshes next,
    /// among those untouched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// The ordering makes the cap safe, since what a pass does not reach leads the next one rather than the same head of the collection being walked forever.
    /// </summary>
    Task<List<TvShowReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document, for the admin unlink, which deletes the shared document rather than detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
