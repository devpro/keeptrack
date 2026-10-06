using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IHouseHistoryRepository : IDataRepository<HouseHistoryModel>
{
    /// <summary>
    /// Deletes every history entry of <paramref name="ownerId"/> for the house, cascading its deletion,
    /// since entries reference their house by id rather than being embedded (see docs/data-model.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForHouseAsync(string houseId, string ownerId, CancellationToken cancellationToken = default);
}
