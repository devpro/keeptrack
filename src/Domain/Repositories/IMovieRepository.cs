using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IMovieRepository : IDataRepository<MovieModel>, IExploreSourceRepository
{
    /// <summary>
    /// Sets <see cref="MovieModel.ReferenceId"/>, <see cref="MovieModel.Title"/>, <see cref="MovieModel.Year"/>
    /// and the denormalized <see cref="MovieModel.ReferenceRating"/>/<see cref="MovieModel.ReferenceRatingScale"/>
    /// (to the reference's canonical values) on every tenant's movie matching this title/year that doesn't
    /// already have a reference link - see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null);

    /// <summary>
    /// Re-propagates the denormalized <see cref="MovieModel.ReferenceRating"/>/<see cref="MovieModel.ReferenceRatingScale"/>
    /// to every tenant movie already linked to <paramref name="referenceId"/>, keeping the copies current after
    /// a periodic reference refresh (unlike <see cref="SetReferenceLinkAsync"/>, this matches by reference id
    /// and so intentionally does touch already-linked documents). Null clears a rating that went away.
    /// </summary>
    Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source);

    /// <summary>
    /// How many linked items are stamped with a rating source other than <paramref name="source"/> (an item
    /// stamped with none at all counts). Lets the admin "recompute" action skip its whole pass when every item
    /// is already on the selected source, instead of rewriting values that are already correct.
    /// </summary>
    Task<long> CountLinkedOnOtherRatingSourceAsync(string source);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's movies that have no <see cref="MovieModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync();
}
