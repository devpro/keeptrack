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
        string? canonicalLanguage = null, string? canonicalIsbn = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Re-propagates the denormalized <see cref="BookModel.ReferenceRating"/>/<see cref="BookModel.ReferenceRatingScale"/>
    /// to every tenant book already linked to <paramref name="referenceId"/> - see <see cref="IMovieRepository.SetReferenceRatingAsync"/>.
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/> (an item
    /// stamped with none at all counts). Lets the admin "recompute" action skip its whole pass when every item
    /// is already on the selected source, instead of rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

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
