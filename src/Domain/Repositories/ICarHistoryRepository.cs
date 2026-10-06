using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

public interface ICarHistoryRepository : IDataRepository<CarHistoryModel>
{
    /// <summary>
    /// Deletes every history entry of <paramref name="ownerId"/> for the car, cascading its deletion, since entries reference their car by id rather than being embedded (see docs/data-model.md's "Child entities" section).
    /// </summary>
    Task<long> DeleteAllForCarAsync(string carId, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Fuel grades this owner already recorded (SP95-E10, Gazole), for the history form's suggestions, like <see cref="IGearRepository.FindDistinctCategoriesAsync"/>.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctFuelCategoriesAsync(string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// How many entries of every tenant point at this station, since <c>car_station</c> is shared.
    /// The admin cannot delete a station in use: deleting it would blank the location of every refuel referencing it, with nothing to recover it from.
    /// </summary>
    Task<long> CountUsingStationAsync(string stationId);

    /// <summary>
    /// Entry count per station id across every tenant, in one grouped aggregation, so the admin catalogue listing every station costs no round trip per row.
    /// </summary>
    Task<Dictionary<string, long>> CountByStationAsync();

    /// <summary>
    /// Re-points every entry from one station to another, for the admin merge of two documents describing one station, which inline creation makes inevitable.
    /// Like <c>IVideoGameRepository.RepointReferenceAsync</c>, it runs before the absorbed document is deleted, or those entries would lose their station.
    /// </summary>
    Task<long> RepointStationAsync(string fromStationId, string toStationId);
}
