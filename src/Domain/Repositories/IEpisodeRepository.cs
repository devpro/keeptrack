using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IEpisodeRepository : IDataRepository<EpisodeModel>
{
    /// <summary>
    /// Every episode of any of the given shows, owner-scoped, in one read.
    /// Watch Next only needs the episodes of shows in progress, so the cost grows with those shows rather than with the whole watch history.
    /// An empty set runs no query.
    /// </summary>
    Task<List<EpisodeModel>> FindByShowIdsAsync(string ownerId, IReadOnlyCollection<string> tvShowIds);

    /// <summary>
    /// Deletes every episode of <paramref name="ownerId"/> for the show, cascading its deletion,
    /// since episodes reference their show by id rather than being embedded (see docs/data-model.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForShowAsync(string tvShowId, string ownerId, CancellationToken cancellationToken = default);
}
