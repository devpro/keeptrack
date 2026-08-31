using System.Collections.Generic;
using System.Threading;
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
    Task<long> DeleteAllForCarAsync(string carId, string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Fuel grades this owner has already recorded (SP95-E10, Gazole, ...), feeding the history form's
    /// suggestion list - the same "suggest what you've already typed" shape as
    /// <see cref="IGearRepository.FindDistinctCategoriesAsync"/>.
    /// </summary>
    Task<IReadOnlyList<string>> FindDistinctFuelCategoriesAsync(string ownerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// How many entries - across every tenant, since <c>car_station</c> is shared and owner-less - point at
    /// this station. Backs the admin refusal to delete a station still in use: a station is only ever
    /// reachable through an entry's <see cref="Domain.Models.CarHistoryModel.StationId"/>, so deleting one
    /// blanks the location of every refuel that referenced it, with nothing to recover it from.
    /// </summary>
    Task<long> CountUsingStationAsync(string stationId);

    /// <summary>
    /// Entry count per station id across every tenant, as one grouped aggregation rather than a count per
    /// station - the admin catalogue lists the whole collection, so a round trip per row is what this
    /// avoids.
    /// </summary>
    Task<Dictionary<string, long>> CountByStationAsync();

    /// <summary>
    /// Re-points every entry from one station to another, for the admin merge of two documents describing
    /// the same physical station (inline creation makes near-duplicates inevitable). Same role as
    /// <c>IVideoGameRepository.RepointReferenceAsync</c> in the reference-merge flow: skipping it would
    /// silently blank those entries' station instead of moving them.
    /// </summary>
    Task<long> RepointStationAsync(string fromStationId, string toStationId);
}
