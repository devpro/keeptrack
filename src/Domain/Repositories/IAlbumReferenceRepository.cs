using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared album reference collection.
/// See <see cref="ITvShowReferenceRepository"/> for why it does not extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IAlbumReferenceRepository
{
    Task<AlbumReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for list-page cover hydration: one query per page, never one per item.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The reference confirmed for this (title, artist), an album's whole identity, which every match path asks before any provider.
    /// <para>
    /// <paramref name="artist"/> is part of the key, not a search hint: two different albums easily share a generic title, so a title alone could link an unrelated album.
    /// See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </para>
    /// <para>
    /// The key has no year: one release exists as many pressings under many years, so a year would only refuse a match the artist already confirmed.
    /// See <see cref="Domain.Services.ReferenceAliasRule.TitleAndCreator"/>.
    /// </para>
    /// </summary>
    Task<AlbumReferenceModel?> FindByTitleCreatorAsync(string title, string artist);

    /// <summary>
    /// Looks up a reference by provider id (its Discogs id), the strongest sign of the same album, whatever its title.
    /// </summary>
    Task<AlbumReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<AlbumReferenceModel> UpsertAsync(AlbumReferenceModel model);

    /// <summary>
    /// Every reference document, for the admin export.
    /// An unpaged read is fine, since this shared metadata is bounded and not per tenant.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindAllAsync();

    /// <summary>
    /// The stalest <paramref name="limit"/> documents the periodic sync refreshes next,
    /// among those untouched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// The ordering makes the cap safe, since what a pass does not reach leads the next one rather than the same head of the collection being walked forever.
    /// </summary>
    Task<List<AlbumReferenceModel>> FindStaleAsync(DateTime cutoff, int limit);

    /// <summary>
    /// Permanently removes a reference document, for the admin unlink, which deletes the shared document rather than detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
