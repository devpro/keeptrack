using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/cars")]
public class CarController(
    IMapper mapper,
    ICarRepository dataRepository,
    ICarHistoryRepository carHistoryRepository,
    CarMetricsService metricsService)
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

        return Ok(Mapper.Map<CarMetricsDto>(metricsService.ComputeMetrics(history.Items)));
    }
}
