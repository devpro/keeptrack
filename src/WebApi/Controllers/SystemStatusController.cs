using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Operational visibility for admins: this instance's configuration plus the shared reference sync lease and recent background jobs.
/// Per-instance fields describe the replica that answered, so other names on refresh show that load balancing works.
/// </summary>
[ApiController]
[Authorize(Policy = "AdminOnly")]
[Route("api/system-status")]
public class SystemStatusController(
    IConfiguration configuration,
    ILeaseRepository leaseRepository,
    IBackgroundJobRepository backgroundJobRepository) : ControllerBase
{
    /// <summary>
    /// The lease name of ReferenceSyncBackgroundService.
    /// </summary>
    private const string ReferenceSyncLeaseName = "reference-sync";

    private const int RecentJobsLimit = 10;

    /// <summary>
    /// The answering instance's configuration and the shared background-work state (sync lease, recent jobs).
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<SystemStatusDto>> Get()
    {
        var appConfiguration = new AppConfiguration(configuration);
        var lease = await leaseRepository.FindAsync(ReferenceSyncLeaseName);
        var recentJobs = await backgroundJobRepository.FindRecentAsync(RecentJobsLimit);

        return Ok(new SystemStatusDto
        {
            InstanceName = Environment.MachineName,
            IsReferenceSyncEnabled = appConfiguration.IsReferenceSyncEnabled,
            // the default provider of automatic resolution, an admin still searching with any registered provider (see ReferenceClientRegistry)
            BookProvider = string.IsNullOrEmpty(appConfiguration.BookReferenceProvider) ? "googlebooks" : appConfiguration.BookReferenceProvider,
            VideoGameProvider = appConfiguration.VideoGameReferenceProvider,
            ReferenceSyncLease = lease is null
                ? null
                : new SystemLeaseDto { Holder = lease.Holder, ExpiresAt = lease.ExpiresAt, IsLive = lease.ExpiresAt > DateTime.UtcNow },
            RecentJobs = recentJobs.ConvertAll(job => new SystemJobDto
            {
                Kind = job.Kind,
                Stage = job.Stage,
                ErrorMessage = job.ErrorMessage,
                CreatedAt = job.CreatedAt
            })
        });
    }
}
