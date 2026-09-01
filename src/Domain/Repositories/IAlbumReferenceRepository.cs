using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less album reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IAlbumReferenceRepository
{
    Task<AlbumReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing list-page image hydration - one query per page instead of one per item.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The reference confirmed for this (title, artist) - an album's whole identity, and the local lookup every match path asks before any provider is called.
    /// <para>
    /// <paramref name="artist"/> is required (not optional) as part of the match key, not just a search hint: two different tenants' different albums can easily share a title - a generic title re-released is common - so a title alone risks silently linking a tenant to another tenant's unrelated album.
    /// See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </para>
    /// <para>
    /// There is deliberately no year in this key, and no year-narrowed variant of it: one release exists as many pressings under as many years (the same reason <c>ReferenceMatchRules.ConfirmedCreatorMatches</c> treats the year as a tie-break for this domain rather than a filter), so a year would only ever refuse a match the artist had already confirmed.
    /// See <see cref="Domain.Services.ReferenceAliasRule.TitleAndCreator"/>.
    /// </para>
    /// </summary>
    Task<AlbumReferenceModel?> FindByTitleCreatorAsync(string title, string artist);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its Discogs master id) - the strongest
    /// possible "is this genuinely the same album" signal, unaffected by title text ever diverging.
    /// </summary>
    Task<AlbumReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<AlbumReferenceModel> UpsertAsync(AlbumReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync should refresh next: never enriched
    /// first, then least-recently enriched, and only those untouched since <paramref name="cutoff"/>.
    /// The ordering is what makes the cap safe - a pass takes the oldest, so what it doesn't reach is first
    /// in line next time, instead of the head of the collection being re-walked forever.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document - backs the admin "unlink" action, which deletes the
    /// shared document outright rather than merely detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
