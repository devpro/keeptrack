using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IVideoGameRepository : IDataRepository<VideoGameModel>
{
    /// <summary>
    /// Sets <see cref="VideoGameModel.ReferenceId"/>, <see cref="VideoGameModel.Title"/> and
    /// <see cref="VideoGameModel.Year"/> (to the reference's canonical values) on every tenant's game matching
    /// this title/year that doesn't already have a reference link - see <see cref="ITvShowRepository.SetReferenceLinkAsync"/>.
    /// <see cref="VideoGameModel.Platform"/>/<see cref="VideoGameModel.State"/> are deliberately never set here -
    /// they describe this tenant's own copy/progress, not the canonical release.
    /// </summary>
    Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null);

    /// <summary>
    /// Distinct (title, year) pairs across every tenant's games that have no <see cref="VideoGameModel.ReferenceId"/>
    /// yet - feeds the admin curation queue.
    /// </summary>
    Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync();
}
