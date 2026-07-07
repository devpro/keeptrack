using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ITvShowRepository : IDataRepository<TvShowModel>
{
    /// <summary>
    /// Sets <see cref="TvShowModel.ReferenceId"/> and <see cref="TvShowModel.Title"/> (to the reference's
    /// canonical name) on every tenant's show matching this title/year that doesn't already have a
    /// reference link - the confirmed cross-tenant propagation for reference-data linking. Also sets
    /// <see cref="TvShowModel.Year"/> to <paramref name="canonicalYear"/> when the reference has one, so a
    /// newly-linked show starts with a trustworthy year instead of whatever the tenant originally guessed
    /// (still freely editable afterward). Otherwise never touches any tenant's own rating/notes/episodes.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's shows that have no <see cref="TvShowModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync();
}
