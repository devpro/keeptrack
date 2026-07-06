using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ITvShowRepository : IDataRepository<TvShowModel>
{
    /// <summary>
    /// Sets <see cref="TvShowModel.ReferenceId"/> on every tenant's show matching this title/year that
    /// doesn't already have one - the confirmed cross-tenant propagation for reference-data linking. Only
    /// this one pointer field is touched, never any tenant's own rating/notes/episodes.
    /// </summary>
    Task<long> SetReferenceIdForTitleYearAsync(string title, int? year, string referenceId);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's shows that have no <see cref="TvShowModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync();
}
