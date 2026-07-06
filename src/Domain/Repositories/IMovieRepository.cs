using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IMovieRepository : IDataRepository<MovieModel>
{
    /// <summary>
    /// Sets <see cref="MovieModel.ReferenceId"/> and <see cref="MovieModel.Title"/> (to the reference's
    /// canonical name) on every tenant's movie matching this title/year that doesn't already have a
    /// reference link - see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's movies that have no <see cref="MovieModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync();
}
