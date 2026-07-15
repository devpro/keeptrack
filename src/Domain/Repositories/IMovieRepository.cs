using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IMovieRepository : IDataRepository<MovieModel>
{
    /// <summary>
    /// Sets <see cref="MovieModel.ReferenceId"/>, <see cref="MovieModel.Title"/> and <see cref="MovieModel.Year"/>
    /// (to the reference's canonical values) on every tenant's movie matching this title/year that doesn't
    /// already have a reference link - see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's movies that have no <see cref="MovieModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
