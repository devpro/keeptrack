using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/houses")]
public class HouseController(
    IMapper mapper,
    IHouseRepository dataRepository,
    IHouseHistoryRepository houseHistoryRepository,
    HouseMetricsService metricsService)
    : DataCrudControllerBase<HouseDto, HouseModel>(mapper, dataRepository)
{
    /// <summary>
    /// Computed yearly cost history for this house - see <see cref="HouseMetricsService"/>.
    /// </summary>
    [HttpGet("{id}/metrics")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<HouseMetricsDto>> GetMetrics(string id)
    {
        var ownerId = this.GetUserId();

        var house = await dataRepository.FindOneAsync(id, ownerId);
        if (house is null) return NotFound();

        var history = await houseHistoryRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new HouseHistoryModel { OwnerId = ownerId, HouseId = id, EventType = default, HistoryDate = default });

        return Ok(Mapper.Map<HouseMetricsDto>(metricsService.ComputeMetrics(history.Items)));
    }

    /// <summary>
    /// HouseHistory is a separate top-level collection referencing its house by id, not an embedded array
    /// (see CLAUDE.md's "Child entities" section) - without this, deleting a house would leave its history
    /// orphaned in MongoDB forever, since it's only ever reachable via the house's own id.
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId) => await houseHistoryRepository.DeleteAllForHouseAsync(id, ownerId);
}
