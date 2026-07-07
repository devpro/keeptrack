using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less TV show reference collection. Deliberately not
/// <see cref="IDataRepository{TModel}"/> - that interface (and its Mongo base class) is hard-constrained
/// to owner-scoped paged CRUD, which doesn't fit a shared lookup table.
/// </summary>
public interface ITvShowReferenceRepository
{
    Task<TvShowReferenceModel?> FindByIdAsync(string id);

    Task<TvShowReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only fallback match (normalized, ignores year) for "or just title" matching when a
    /// title+year lookup finds nothing - e.g. the tenant's recorded year is wrong or missing.
    /// </summary>
    Task<TvShowReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its TMDB id) - the strongest possible
    /// "is this genuinely the same show" signal, unaffected by title text ever diverging. See
    /// <see cref="IPersonReferenceRepository.FindByExternalIdAsync"/> for the equivalent on cast members.
    /// </summary>
    Task<TvShowReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<TvShowReferenceModel> UpsertAsync(TvShowReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<TvShowReferenceModel>> FindAllAsync();
}
