using System.Collections.Generic;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Global, owner-less application settings an admin can change at runtime, all kept in one shared
/// <c>app_setting</c> collection (a single document) rather than a collection per setting - a new setting
/// adds a field/accessor here, never a new collection. Purpose-built like <see cref="ILeaseRepository"/>,
/// so it doesn't extend the owner-scoped <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IAppSettingRepository
{
    /// <summary>
    /// The admin's per-domain primary rating-source overrides, keyed by domain (empty when none has been
    /// set) - which provider score is denormalized onto tenant items as the pill/sort value. A domain with
    /// no entry falls back to its code default (see <c>RatingSourceCatalog</c>).
    /// </summary>
    Task<IReadOnlyDictionary<string, string>> GetReferenceRatingSourcesAsync();

    /// <summary>
    /// Sets (or replaces) the primary rating source for one domain. Upserts the single settings document.
    /// </summary>
    Task SetReferenceRatingSourceAsync(string domainKey, string source);
}
