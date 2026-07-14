using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ICarHistoryRepository : IDataRepository<CarHistoryModel>
{
    /// <summary>
    /// Deletes every history entry owned by <paramref name="ownerId"/> for the given car - used to cascade
    /// a car deletion, since CarHistory is a separate top-level collection referencing its parent by id
    /// rather than an embedded array (see CLAUDE.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForCarAsync(string carId, string ownerId);
}
