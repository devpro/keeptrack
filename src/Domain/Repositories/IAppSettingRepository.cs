using System.Collections.Generic;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Global settings an admin changes at runtime, all in the single document of <c>app_setting</c>.
/// A new setting adds a field and an accessor here, never a new collection.
/// Purpose-built like <see cref="ILeaseRepository"/>, so it does not extend the owner-scoped <see cref="IDataRepository{TModel}"/>.
/// </summary>
public interface IAppSettingRepository
{
    /// <summary>
    /// The admin's primary rating source per domain, empty when none is set: the score copied onto tenant items for display and sorting.
    /// A domain with no entry uses its default (see <c>RatingSourceCatalog</c>).
    /// </summary>
    Task<IReadOnlyDictionary<string, string>> GetReferenceRatingSourcesAsync();

    /// <summary>
    /// Sets the primary rating source for one domain, upserting the settings document.
    /// </summary>
    Task SetReferenceRatingSourceAsync(string domainKey, string source);

    /// <summary>
    /// Whether Explore shows TMDB ratings for movies and TV shows even when IMDb is the primary source, which avoids an OMDb lookup per title.
    /// False by default.
    /// </summary>
    Task<bool> GetExploreUseTmdbAsync();

    /// <summary>Sets the Explore "use TMDB ratings" flag, upserting the settings document.</summary>
    Task SetExploreUseTmdbAsync(bool useTmdb);
}
