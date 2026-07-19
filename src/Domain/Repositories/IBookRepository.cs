using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IBookRepository : IDataRepository<BookModel>
{
    /// <summary>
    /// Sets <see cref="BookModel.ReferenceId"/>, <see cref="BookModel.Title"/>, <see cref="BookModel.Year"/>,
    /// <see cref="BookModel.Author"/>, <see cref="BookModel.Genre"/>, <see cref="BookModel.Language"/> and
    /// <see cref="BookModel.Isbn"/> (to the reference's canonical values) on every tenant's book matching
    /// this title/year that doesn't already have a reference link - see
    /// <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalAuthor = null, string? canonicalGenre = null,
        string? canonicalLanguage = null, string? canonicalIsbn = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's books that have no <see cref="BookModel.ReferenceId"/>
    /// yet - feeds the admin curation queue. <c>Isbn</c> (like <c>Creator</c>) is a search-prefill
    /// convenience only, taken from one of the matching tenant items - Book is the only
    /// <c>FindDistinctUnresolvedTitleYearsAsync</c> that returns one, since it's the only domain with an
    /// ISBN concept; the admin controller's <c>GetUnresolved</c> action handles Book separately from the
    /// other four reference domains for exactly this reason.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator, string? Isbn)>> FindDistinctUnresolvedTitleYearsAsync();
}
