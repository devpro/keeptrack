using System.Collections.Generic;
using System.Threading.Tasks;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// The owner-scoped projections the Explore feature needs from a trackable collection to answer "does this
/// caller already have this title?" - implemented by every domain Explore can suggest for (movies, TV shows,
/// video games today). Declared once here so <c>ExploreService</c> can pick one repository per domain rather
/// than branching per method, and so the three interfaces don't each re-declare the same pair.
/// </summary>
public interface IExploreSourceRepository
{
    /// <summary>
    /// Distinct non-empty reference ids this owner already tracks - the primary "already added" exclusion
    /// (a reference the owner already has an item linked to is never suggested).
    /// </summary>
    Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync(string ownerId);

    /// <summary>
    /// Distinct raw titles this owner tracks - the fallback exclusion, since an item added manually or
    /// imported may never have been linked to a reference document and so is invisible to
    /// <see cref="FindLinkedReferenceIdsAsync"/>. Callers normalize before comparing.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctTitlesAsync(string ownerId);
}
