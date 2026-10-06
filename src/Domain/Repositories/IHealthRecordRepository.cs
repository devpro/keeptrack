using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface IHealthRecordRepository : IDataRepository<HealthRecordModel>
{
    /// <summary>
    /// Distinct specialties this owner already recorded, for the journal form's suggestions.
    /// Owner-scoped, so one account's medical history is never suggested to another.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctSpecialtiesAsync(string ownerId);

    /// <summary>
    /// Distinct practitioner names this owner already recorded, like <see cref="FindDistinctSpecialtiesAsync"/>.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctPractitionersAsync(string ownerId);

    /// <summary>
    /// Deletes every record of <paramref name="ownerId"/> for the profile, cascading its deletion, since records reference their profile by id rather than being embedded (see docs/data-model.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId, CancellationToken cancellationToken = default);
}
