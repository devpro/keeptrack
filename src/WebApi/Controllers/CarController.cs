using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/cars")]
public class CarController(
    IDtoMapper<CarDto, CarModel> mapper,
    ICarRepository dataRepository,
    ICarHistoryRepository carHistoryRepository,
    CarMetricsService metricsService,
    CarMetricsDtoMapper metricsMapper)
    : DataCrudControllerBase<CarDto, CarModel>(mapper, dataRepository)
{
    /// <summary>
    /// Computed fuel/electric consumption, cost history, mileage warnings and next-maintenance estimate for
    /// this car - see <see cref="CarMetricsService"/>.
    /// </summary>
    [HttpGet("{id}/metrics")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<CarMetricsDto>> GetMetrics(string id)
    {
        var ownerId = this.GetUserId();

        var car = await dataRepository.FindOneAsync(id, ownerId);
        if (car is null) return NotFound();

        var history = await carHistoryRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new CarHistoryModel { OwnerId = ownerId, CarId = id, EventType = default, HistoryDate = default });

        return Ok(metricsMapper.ToDto(metricsService.ComputeMetrics(history.Items)));
    }

    /// <summary>
    /// CarHistory is a separate top-level collection referencing its car by id, not an embedded array
    /// (see CLAUDE.md's "Child entities" section) - without this, deleting a car would leave its fuel/
    /// maintenance history orphaned in MongoDB forever, since it's only ever reachable via the car's own id.
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId) => await carHistoryRepository.DeleteAllForCarAsync(id, ownerId);
}
