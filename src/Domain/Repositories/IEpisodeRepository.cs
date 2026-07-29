using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IEpisodeRepository : IDataRepository<EpisodeModel>
{
    /// <summary>
    /// Batched read of every episode belonging to any of the given shows (owner-scoped).
    /// Backs Watch Next, which only needs episodes for the (small) set of shows that can actually appear in
    /// its result - fetching the whole owner's episode history and discarding non-current shows in memory
    /// scaled with total watch history instead of with in-progress shows. An empty set returns no query.
    /// </summary>
    Task<List<EpisodeModel>> FindByShowIdsAsync(string ownerId, IReadOnlyCollection<string> tvShowIds);
}
