using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less video game reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IVideoGameReferenceRepository
{
    Task<VideoGameReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing list-page image hydration - one query per page instead of one per item.
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    Task<VideoGameReferenceModel?> FindByTitleYearAsync(string title, int? year);

    /// <summary>
    /// Title-only fallback match (normalized, ignores year) for "or just title" matching when a
    /// title+year lookup finds nothing.
    /// </summary>
    Task<VideoGameReferenceModel?> FindByTitleAsync(string title);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its RAWG game id) - the strongest
    /// possible "is this genuinely the same game" signal, unaffected by title text ever diverging.
    /// </summary>
    Task<VideoGameReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<VideoGameReferenceModel> UpsertAsync(VideoGameReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<VideoGameReferenceModel>> FindAllAsync();

    /// <summary>
    /// Permanently removes a reference document - backs the admin "unlink" action, which deletes the
    /// shared document outright rather than merely detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
