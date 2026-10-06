using System.Collections.Generic;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// The owner-scoped projections Explore needs from a collection to know whether the caller already has a title, implemented by every domain Explore suggests for.
/// Declared once, so <c>ExploreService</c> picks one repository per domain rather than branching per method.
/// </summary>
public interface IExploreSourceRepository
{
    /// <summary>
    /// Distinct reference ids this owner already tracks: the main exclusion, since a reference the owner has an item linked to is never suggested.
    /// </summary>
    Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync(string ownerId);

    /// <summary>
    /// Distinct raw titles this owner tracks: the fallback exclusion, since an item never linked is invisible to <see cref="FindLinkedReferenceIdsAsync"/>.
    /// Callers normalize before comparing.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctTitlesAsync(string ownerId);
}
