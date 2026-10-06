using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IBookRepository : IDataRepository<BookModel>
{
    /// <summary>
    /// Sets <see cref="BookModel.ReferenceId"/>, <see cref="BookModel.Title"/>, <see cref="BookModel.Year"/>, <see cref="BookModel.Author"/>, <see cref="BookModel.Genre"/>,
    /// <see cref="BookModel.Language"/>
    /// and <see cref="BookModel.Isbn"/> to the reference's values on the records <paramref name="target"/> names (see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>).
    /// </summary>
    Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalAuthor = null, string? canonicalGenre = null,
        string? canonicalLanguage = null, string? canonicalIsbn = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Copies the rating again onto every book linked to <paramref name="referenceId"/> (see <see cref="IMovieRepository.SetReferenceRatingAsync"/>).
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/>, an unstamped item included.
    /// The admin recompute skips its whole pass when this is zero, rather than rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's unlinked books, for the admin queue.
    /// <c>Isbn</c>, like <c>Creator</c>, only prefills the search, taken from one matching item.
    /// Books alone have an ISBN, which is why the admin controller's <c>GetUnresolved</c> handles them apart from the other domains.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator, string? Isbn)>> FindDistinctUnresolvedTitleYearsAsync();
}
