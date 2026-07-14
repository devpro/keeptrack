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
    /// <paramref name="artist"/> is required (not optional) as part of the match key, not just a search
    /// hint: two different tenants' different albums can easily share the same (title, year) - a generic
    /// title re-released the same year is common - so title+year alone risks silently linking a tenant
    /// to another tenant's unrelated album. See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </summary>
    Task<AlbumReferenceModel?> FindByTitleYearAsync(string title, int? year, string artist);

    /// <summary>
    /// Title-only fallback match (normalized, ignores year) for "or just title" matching when a
    /// title+year lookup finds nothing - still requires <paramref name="artist"/> to match, for the same
    /// reason <see cref="FindByTitleYearAsync"/> does.
    /// </summary>
    Task<AlbumReferenceModel?> FindByTitleAsync(string title, string artist);

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
}
