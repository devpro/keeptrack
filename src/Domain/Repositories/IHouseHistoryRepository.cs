using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IHouseHistoryRepository : IDataRepository<HouseHistoryModel>
{
    /// <summary>
    /// Deletes every history entry owned by <paramref name="ownerId"/> for the given house - used to cascade
    /// a house deletion, since HouseHistory is a separate top-level collection referencing its parent by id
    /// rather than an embedded array (see CLAUDE.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForHouseAsync(string houseId, string ownerId);
}
