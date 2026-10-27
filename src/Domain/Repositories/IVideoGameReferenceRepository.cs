using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared video game reference collection.
/// See <see cref="ITvShowReferenceRepository"/> for why it does not extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IVideoGameReferenceRepository
{
    Task<VideoGameReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for list-page cover hydration: one query per page, never one per item.
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The <paramref name="provider"/> id of each given reference, projected server side from <c>external_ids</c> alone.
    /// The Explore exclusion needs one string per reference, where <see cref="FindByIdsAsync"/> would fetch whole documents.
    /// </summary>
    Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider);

    /// <summary>
    /// One page of (id, ratings) for the admin rating recompute (see <see cref="IMovieReferenceRepository.FindRatingsAsync"/>).
    /// </summary>
    Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit);

    Task<VideoGameReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only lookup (normalized, any year), returning a match only when exactly one reference has this title.
    /// </summary>
    Task<VideoGameReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference by provider id (an IGDB or RAWG id), the strongest sign of the same game, whatever its title.
    /// </summary>
    Task<VideoGameReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<VideoGameReferenceModel> UpsertAsync(VideoGameReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync refreshes next,
    /// among those untouched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// The ordering makes the cap safe, since what a pass does not reach leads the next one rather than the same head of the collection being walked forever.
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Every reference with no id from <paramref name="provider"/>: the admin reconciliation backlog, and exactly the set the Explore exclusion by provider id cannot see.
    /// <para>
    /// Whole documents rather than a projection, since the queue shows the title, year, every id held and the last adoption attempt,
    /// and a game reference has no episode guide to make that expensive.
    /// Unpaged like <see cref="FindAllAsync"/>, since the backlog is a fraction of a small collection.
    /// </para>
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindWithoutExternalIdAsync(string provider);

    /// <summary>
    /// Permanently removes a reference document, for the admin unlink, which deletes the shared document rather than detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
