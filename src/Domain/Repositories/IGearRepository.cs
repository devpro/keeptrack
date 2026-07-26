using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IGearRepository : IDataRepository<GearModel>
{
    /// <summary>
    /// Distinct, non-empty <see cref="GearModel.Category"/> values across this tenant's gear, sorted
    /// alphabetically - feeds the list page's category filter buttons and the detail page's suggested
    /// values. One gear item has exactly one category (unlike a blog's tags), so this is a plain
    /// distinct scan, not a tag-cloud aggregation.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctCategoriesAsync(string ownerId);
}
