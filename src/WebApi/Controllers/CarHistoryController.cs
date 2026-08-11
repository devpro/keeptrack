using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/car-history")]
public class CarHistoryController(
    IDtoMapper<CarHistoryDto, CarHistoryModel> mapper,
    ICarHistoryRepository dataRepository,
    ICarStationRepository stationRepository)
    : DataCrudControllerBase<CarHistoryDto, CarHistoryModel>(mapper, dataRepository)
{
    /// <summary>
    /// Fuel grades this account has already recorded, feeding the history form's suggestion list - the same
    /// "suggest what you've already typed" shape as <c>GearController.GetCategories</c>.
    /// </summary>
    [HttpGet("fuel-categories")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<IReadOnlyList<string>>> GetFuelCategories()
    {
        var categories = await dataRepository.FindDistinctFuelCategoriesAsync(this.GetUserId());
        return Ok(categories);
    }

    /// <summary>
    /// Fills each Refuel entry's station name and city from the shared station catalogue, one batched
    /// lookup per page.
    /// </summary>
    protected override Task OnListMappedAsync(List<CarHistoryDto> dtos)
        => CarStationHydrator.HydrateAsync(dtos, stationRepository);
}
