using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for <see cref="ExploreDismissalModel"/>.
/// Not an <see cref="IDataRepository{TModel}"/>, since dismissals are only looked up by owner, item type and source, never paged or searched.
/// </summary>
public interface IExploreDismissalRepository
{
    /// <summary>
    /// The <paramref name="externalSource"/> ids this owner dismissed for <paramref name="type"/>, part of the Explore exclusion.
    /// Scoped to the source, so ids are read back in the number space they were written in.
    /// </summary>
    Task<IReadOnlyList<string>> FindDismissedExternalIdsAsync(string ownerId, ExploreItemType type, string externalSource);

    /// <summary>Records a dismissal, idempotently.</summary>
    Task AddAsync(ExploreDismissalModel model);

    /// <summary>Undoes a dismissal so the title can be suggested again.</summary>
    Task RemoveAsync(string ownerId, ExploreItemType type, string externalSource, string externalId);
}
