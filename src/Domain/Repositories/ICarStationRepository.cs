using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Repository for the shared <c>car_station</c> collection.
/// Like the <c>*_reference</c> repositories, it does not extend <see cref="IDataRepository{TModel}"/>, which is constrained to owner-scoped paged CRUD.
/// </summary>
public interface ICarStationRepository
{
    Task<CarStationModel?> FindByIdAsync(string id);

    /// <summary>
    /// Batched id lookup for car history hydration: one query per page, never one per entry.
    /// </summary>
    Task<List<CarStationModel>> FindByIdsAsync(IReadOnlyCollection<string> ids);

    /// <summary>
    /// The whole catalogue, ordered by brand then city.
    /// Unpaged, since it is small and shared, and the station picker needs all of it at once.
    /// </summary>
    Task<List<CarStationModel>> FindAllAsync();

    /// <summary>
    /// Looks a station up by its natural key (normalized brand, city, postal code), so a member's inline creation reuses a station rather than minting a duplicate.
    /// </summary>
    Task<CarStationModel?> FindByNaturalKeyAsync(string brandName, string? city, string? postalCode);

    /// <summary>
    /// Creates or updates a station, stamping the normalized natural-key fields.
    /// <see cref="FindByNaturalKeyAsync"/> avoids duplicates, and the unique index guarantees there are none.
    /// </summary>
    Task<CarStationModel> UpsertAsync(CarStationModel model);

    Task<bool> DeleteAsync(string id);
}
