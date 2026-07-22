using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less book reference collection. See
/// <see cref="ITvShowReferenceRepository"/> for why this doesn't extend <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IBookReferenceRepository
{
    Task<BookReferenceModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing list-page image hydration - one query per page instead of one per item.
    /// </summary>
    Task<List<BookReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// <paramref name="author"/> is required (not optional) as part of the match key, not just a search
    /// hint: two different tenants' different books can easily share the same (title, year) - a generic
    /// title re-published the same year is common - so title+year alone risks silently linking a tenant
    /// to another tenant's unrelated book. See <see cref="Domain.Models.ReferenceMatchModel.Creator"/>.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author);

    /// <summary>
    /// Title-only fallback match (normalized, ignores year) for "or just title" matching when a
    /// title+year lookup finds nothing - still requires <paramref name="author"/> to match, for the same
    /// reason <see cref="FindByTitleYearAsync"/> does.
    /// </summary>
    Task<BookReferenceModel?> FindByTitleAsync(string title, string author);

    /// <summary>
    /// Looks up a reference document by external provider id (e.g. its Open Library work id) - the
    /// strongest possible "is this genuinely the same book" signal, unaffected by title text ever diverging.
    /// </summary>
    Task<BookReferenceModel?> FindByExternalIdAsync(string provider, string externalId);

    Task<BookReferenceModel> UpsertAsync(BookReferenceModel model);

    /// <summary>
    /// Every reference document, for admin export. Bounded, shared metadata (not per-tenant), so a
    /// full unpaged read is fine.
    /// </summary>
    Task<List<BookReferenceModel>> FindAllAsync();

    /// <summary>
    /// Permanently removes a reference document - backs the admin "unlink" action, which deletes the
    /// shared document outright rather than merely detaching one tenant's link.
    /// </summary>
    Task DeleteAsync(string id);
}
