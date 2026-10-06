using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared movie reference collection.
/// See <see cref="ITvShowReferenceRepository"/> for why it does not extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IMovieReferenceRepository
{
    Task<MovieReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for list-page cover hydration: one query per page, never one per item.
    /// </summary>
    Task<List<MovieReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The <paramref name="provider"/> id of each given reference, projected server side from <c>external_ids</c> alone.
    /// The Explore exclusion needs one string per reference, where <see cref="FindByIdsAsync"/> would fetch whole documents.
    /// </summary>
    Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider);

    /// <summary>
    /// One page of (id, ratings) for the admin rating recompute, ordered by id, after <paramref name="afterId"/> (null for the first page).
    /// Projected server side, since the recompute reads two fields and <see cref="FindAllAsync"/> would load whole documents, synopsis and cast included.
    /// Paged by an id cursor, so a growing collection does not grow the memory one recompute needs.
    /// </summary>
    Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit);

    Task<MovieReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only fallback (normalized, any year), asked when the tenant has no year.
    /// It returns a match only when exactly one reference has this title, since ambiguous and not found mean the same to a caller that must not guess.
    /// </summary>
    Task<MovieReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference by provider id (its TMDB id), the strongest sign of the same movie, whatever its title.
    /// </summary>
    Task<MovieReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<MovieReferenceModel> UpsertAsync(MovieReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<MovieReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync refreshes next, among those untouched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// The ordering makes the cap safe, since what a pass does not reach leads the next one rather than the same head of the collection being walked forever.
    /// </summary>
    Task<List<MovieReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document, for the admin unlink, which deletes the shared document rather than detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
