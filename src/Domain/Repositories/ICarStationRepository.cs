using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared, owner-less <c>car_station</c> collection. Like the <c>*_reference</c>
/// repositories it deliberately does not extend <see cref="IDataRepository{TModel}"/>, which is
/// hard-constrained to owner-scoped paged CRUD over <see cref="Common.System.IHasIdAndOwnerId"/>.
/// </summary>
public interface ICarStationRepository
{
    Task<CarStationModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup backing car-history list hydration - one query per page instead of one per entry,
    /// the same shape as the reference repositories' own <c>FindByIdsAsync</c>.
    /// </summary>
    Task<List<CarStationModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The whole catalogue, ordered by brand then city. Unpaged like the reference exports and acceptable
    /// for the same reason: this data is small, shared, and the station picker needs all of it at once.
    /// </summary>
    Task<List<CarStationModel>> FindAllAsync();

    /// <summary>
    /// Looks a station up by its natural key (normalized brand name + city + postal code) - what makes a
    /// member's inline "create this station" idempotent instead of minting a duplicate per refuel.
    /// </summary>
    Task<CarStationModel?> FindByNaturalKeyAsync(string brandName, string? city, string? postalCode);

    /// <summary>
    /// Creates or updates a station, stamping the normalized natural-key fields. The application check in
    /// <see cref="FindByNaturalKeyAsync"/> is what's supposed to prevent duplicates; the collection's
    /// unique index is what guarantees it.
    /// </summary>
    Task<CarStationModel> UpsertAsync(CarStationModel model);

    Task<bool> DeleteAsync(string id);
}
