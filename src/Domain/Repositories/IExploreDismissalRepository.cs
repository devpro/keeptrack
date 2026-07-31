using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="ExploreDismissalModel"/> - purpose-built rather than
/// <see cref="IDataRepository{TModel}"/> (owner-scoped, looked up only by (owner, item type, source), never
/// paged/searched), same reasoning as <see cref="IWishlistShareRepository"/>.
/// </summary>
public interface IExploreDismissalRepository
{
    /// <summary>
    /// The <paramref name="externalSource"/> ids this owner has dismissed for <paramref name="type"/> - part of
    /// the Explore exclusion set. Scoped to the source so ids are always read back in the number space they
    /// were written in.
    /// </summary>
    Task<IReadOnlyList<string>> FindDismissedExternalIdsAsync(string ownerId, ExploreItemType type, string externalSource);

    /// <summary>Records a dismissal. Idempotent: dismissing the same (owner, item type, source, external id) twice is a no-op.</summary>
    Task AddAsync(ExploreDismissalModel model);

    /// <summary>Undoes a dismissal so the title can be suggested again. Owner-scoped.</summary>
    Task RemoveAsync(string ownerId, ExploreItemType type, string externalSource, string externalId);
}
