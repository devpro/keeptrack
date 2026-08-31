using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IHealthRecordRepository : IDataRepository<HealthRecordModel>
{
    /// <summary>
    /// Distinct specialties this owner has already recorded, feeding the journal form's suggestion list.
    /// Owner-scoped like every other query here, which is what keeps one account's medical history from
    /// being suggested to another - see <c>IGearRepository.FindDistinctCategoriesAsync</c> for the shape.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctSpecialtiesAsync(string ownerId);

    /// <summary>
    /// Distinct practitioner names this owner has already recorded - same owner-scoped suggestion shape as
    /// <see cref="FindDistinctSpecialtiesAsync"/>.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctPractitionersAsync(string ownerId);

    /// <summary>
    /// Deletes every record owned by <paramref name="ownerId"/> for the given profile - used to cascade
    /// a profile deletion, since HealthRecord is a separate top-level collection referencing its parent by
    /// id rather than an embedded array (see CLAUDE.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId, CancellationToken cancellationToken = default);
}
