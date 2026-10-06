using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IGearRepository : IDataRepository<GearModel>
{
    /// <summary>
    /// Distinct <see cref="GearModel.Category"/> values of this tenant's gear, sorted, for the list page's category filters and the detail page's suggestions.
    /// One item has exactly one category, so this is a plain distinct scan.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctCategoriesAsync(string ownerId);
}
