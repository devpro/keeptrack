using System.Threading;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/cars")]
public class CarController(
    IDtoMapper<CarDto, CarModel> mapper,
    ICarRepository dataRepository,
    ICarHistoryRepository carHistoryRepository,
    CarMetricsDtoMapper metricsMapper)
    : DataCrudControllerBase<CarDto, CarModel>(mapper, dataRepository)
{
    /// <summary>
    /// Computed consumption, cost history, mileage warnings and last records for this car (see <see cref="CarMetricsService"/>).
    /// </summary>
    [HttpGet("{id}/metrics")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<CarMetricsDto>> GetMetrics(string id, CancellationToken cancellationToken)
    {
        var ownerId = this.GetUserId();

        var car = await dataRepository.FindOneAsync(id, ownerId, cancellationToken);
        if (car is null) return NotFound();

        var history = await carHistoryRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new CarHistoryModel { OwnerId = ownerId, CarId = id, EventType = default, HistoryDate = default }, cancellationToken: cancellationToken);

        return Ok(metricsMapper.ToDto(CarMetricsService.ComputeMetrics(history.Items)));
    }

    /// <summary>
    /// Cascades to the car's history, a separate collection reachable only through the car's id, which would otherwise be orphaned forever.
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId, CancellationToken cancellationToken)
    {
        await carHistoryRepository.DeleteAllForCarAsync(id, ownerId, cancellationToken);
    }
}
