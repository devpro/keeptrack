using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Fills the display-only <see cref="CarHistoryDto.StationBrandName"/>/<see cref="CarHistoryDto.StationCity"/>
/// on a page of history entries from the shared <c>car_station</c> collection, with a single batched
/// lookup - the same one-query-per-page rule as <see cref="ReferenceImageHydrator"/>, and the reason the
/// station's name and location are stored once rather than copied onto every refuel.
/// Shared by <see cref="CarHistoryController"/> and the shared-with-me car read so the collect/lookup/apply
/// logic exists once.
/// </summary>
public static class CarStationHydrator
{
    public static async Task HydrateAsync(IReadOnlyList<CarHistoryDto> entries, ICarStationRepository stationRepository)
    {
        // distinct, non-empty ids only - an entry with no station (every Maintenance/Other one) contributes
        // nothing, and "" is the pre-Mapperly generation of "unset" (see CLAUDE.md's UnresolvedFilter gotcha)
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
