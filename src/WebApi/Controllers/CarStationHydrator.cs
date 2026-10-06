using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Fills <see cref="CarHistoryDto.StationBrandName"/> and <see cref="CarHistoryDto.StationCity"/> on a page of history entries from <c>car_station</c>, in one batched lookup like <see cref="ReferenceImageHydrator"/>.
/// Shared by <see cref="CarHistoryController"/> and the shared car read.
/// </summary>
public static class CarStationHydrator
{
    public static async Task HydrateAsync(IReadOnlyList<CarHistoryDto> entries, ICarStationRepository stationRepository)
    {
        // distinct non-empty ids, since Maintenance and Other entries have no station, and older documents store "" for unset (see docs/data-model.md)
        var ids = entries.Select(x => x.StationId).OfType<string>().Where(x => x.Length > 0).Distinct().ToList();
        if (ids.Count == 0) return;

        var stationsById = (await stationRepository.FindByIdsAsync(ids))
            .Where(x => !string.IsNullOrEmpty(x.Id))
            .ToDictionary(x => x.Id!);

        foreach (var entry in entries)
        {
            if (!string.IsNullOrEmpty(entry.StationId) && stationsById.TryGetValue(entry.StationId, out var station))
            {
                entry.StationBrandName = station.BrandName;
                entry.StationCity = station.City;
            }
        }
    }
}
