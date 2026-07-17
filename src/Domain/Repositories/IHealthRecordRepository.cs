using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IHealthRecordRepository : IDataRepository<HealthRecordModel>
{
    /// <summary>
    /// Deletes every record owned by <paramref name="ownerId"/> for the given profile - used to cascade
    /// a profile deletion, since HealthRecord is a separate top-level collection referencing its parent by
    /// id rather than an embedded array (see CLAUDE.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId);
}
