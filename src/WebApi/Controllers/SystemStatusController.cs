using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Day-2 operational visibility for admins: this instance's own configuration plus the shared
/// (MongoDB-backed) reference-sync lease and recent background jobs. Per-instance fields describe
/// whichever replica answered the request - deliberately so, since seeing different instance names on
/// refresh is itself evidence that load balancing across replicas works.
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
    /// Matches ReferenceSyncBackgroundService's lease name - the one lease this app has today.
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
            // mirrors Program.cs's provider switch default - update both if a second provider ships
            BookProvider = string.IsNullOrEmpty(appConfiguration.BookReferenceProvider) ? "OpenLibrary" : appConfiguration.BookReferenceProvider,
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
