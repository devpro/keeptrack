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
    /// Computed metrics for this profile: yearly costs after reimbursements, last visit per practitioner,
    /// and paid records still waiting on a reimbursement - see <see cref="HealthMetricsService"/>.
    /// </summary>
    [HttpGet("{id}/metrics")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<HealthMetricsDto>> GetMetrics(string id)
    {
        var ownerId = this.GetUserId();

        var profile = await dataRepository.FindOneAsync(id, ownerId);
        if (profile is null) return NotFound();

        var records = await healthRecordRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new HealthRecordModel { OwnerId = ownerId, HealthProfileId = id, EventType = default, HistoryDate = default });

        return Ok(metricsMapper.ToDto(HealthMetricsService.ComputeMetrics(records.Items)));
    }

    /// <summary>
    /// HealthRecord is a separate top-level collection referencing its profile by id, not an embedded array (see CLAUDE.md's "Child entities" section) -
    /// without this, deleting a profile would leave its journal orphaned in MongoDB forever, since it's only ever reachable via the profile's own id.
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId)
    {
        await healthRecordRepository.DeleteAllForProfileAsync(id, ownerId);
    }
}
