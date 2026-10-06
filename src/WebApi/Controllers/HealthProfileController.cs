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
[Route("api/health-profiles")]
public class HealthProfileController(
    IDtoMapper<HealthProfileDto, HealthProfileModel> mapper,
    IHealthProfileRepository dataRepository,
    IHealthRecordRepository healthRecordRepository,
    HealthMetricsDtoMapper metricsMapper)
    : DataCrudControllerBase<HealthProfileDto, HealthProfileModel>(mapper, dataRepository)
{
    /// <summary>
    /// Computed metrics for this profile: yearly costs after reimbursements, the last visit per specialty,
    /// and paid records still waiting on a reimbursement (see <see cref="HealthMetricsService"/>).
    /// </summary>
    [HttpGet("{id}/metrics")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<HealthMetricsDto>> GetMetrics(string id, CancellationToken cancellationToken)
    {
        var ownerId = this.GetUserId();

        var profile = await dataRepository.FindOneAsync(id, ownerId, cancellationToken);
        if (profile is null) return NotFound();

        var records = await healthRecordRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new HealthRecordModel { OwnerId = ownerId, HealthProfileId = id, EventType = default, HistoryDate = default }, cancellationToken: cancellationToken);

        return Ok(metricsMapper.ToDto(HealthMetricsService.ComputeMetrics(records.Items)));
    }

    /// <summary>
    /// Cascades to the profile's journal, a separate collection reachable only through the profile's id,
    /// which would otherwise be orphaned forever (see docs/data-model.md's "Child entities" section).
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId, CancellationToken cancellationToken)
    {
        await healthRecordRepository.DeleteAllForProfileAsync(id, ownerId, cancellationToken);
    }
}
