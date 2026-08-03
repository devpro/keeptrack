using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less movie reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IMovieReferenceRepository
{
    Task<MovieReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing list-page image hydration - one query per page instead of one per item.
    /// </summary>
    Task<List<MovieReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The <paramref name="provider"/> id of each of the given references, read with a server-side projection
    /// over <c>external_ids</c> alone - the Explore exclusion set wants one string per reference, and
    /// <see cref="FindByIdsAsync"/> would fetch whole documents to supply it.
    /// </summary>
    Task<IReadOnlyList<string>> FindExternalIdsAsync(IReadOnlyCollection<string> ids, string provider);

    /// <summary>
    /// One page of (id, ratings) for the admin rating recompute, ordered by id and starting after
    /// <paramref name="afterId"/> (null for the first page). Another server-side projection, for the same
    /// reason as <see cref="FindExternalIdsAsync"/>: the recompute reads two fields per document, and
    /// <see cref="FindAllAsync"/> would haul whole documents - synopsis, cast, matched aliases - to supply
    /// them. Paged by id cursor rather than read whole, so a growing collection can't grow the memory one
    /// recompute needs.
    /// </summary>
    Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync(string? afterId, int limit);

    Task<MovieReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only fallback match (normalized, ignores year) for "or just title" matching when a
    /// title+year lookup finds nothing - e.g. the tenant's recorded year is wrong or missing.
    /// </summary>
    Task<MovieReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its TMDB id) - the strongest possible
    /// "is this genuinely the same movie" signal, unaffected by title text ever diverging. See
    /// <see cref="IPersonReferenceRepository.FindByExternalIdAsync"/> for the equivalent on cast members.
    /// </summary>
    Task<MovieReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<MovieReferenceModel> UpsertAsync(MovieReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<MovieReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync should refresh next: never enriched
    /// first, then least-recently enriched, and only those untouched since <paramref name="cutoff"/>.
    /// The ordering is what makes the cap safe - a pass takes the oldest, so what it doesn't reach is first
    /// in line next time, instead of the head of the collection being re-walked forever.
    /// </summary>
    Task<List<MovieReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document - backs the admin "unlink" action, which deletes the
    /// shared document outright rather than merely detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
