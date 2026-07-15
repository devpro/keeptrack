using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IBookRepository : IDataRepository<BookModel>
{
    /// <summary>
    /// Sets <see cref="BookModel.ReferenceId"/>, <see cref="BookModel.Title"/>, <see cref="BookModel.Year"/>,
    /// <see cref="BookModel.Author"/> and <see cref="BookModel.Genre"/> (to the reference's canonical values)
    /// on every tenant's book matching this title/year that doesn't already have a reference link - see
    /// <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalAuthor = null, string? canonicalGenre = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's books that have no <see cref="BookModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
