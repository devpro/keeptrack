using System.Diagnostics.CodeAnalysis;
using Keeptrack.WebApi.Controllers;
using Keeptrack.WebApi.Jobs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import")]
public class TvTimeImportController(JobStore<ImportStage, ImportResultDto> jobStore, IServiceScopeFactory scopeFactory) : ControllerBase
{
    /// <summary>
    /// Starts importing a TV Time GDPR export (the zip TV Time sends for a "Download my data" request) as an upsert.
    /// Runs in the background, its progress polled through <see cref="GetStatus"/> with the returned job id.
    /// </summary>
    [HttpPost("tv-time")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(202)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (50 MB), deliberately above Sonar's 8 MB default: " +
                        "a TV Time GDPR export zip spanning years of episode history genuinely exceeds 8 MB, " +
                        "and the endpoint is admin-of-your-own-data, authenticated, member-only.")]
    public async Task<ActionResult<ImportJobDto>> ImportTvTime(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        // buffered first, since IFormFile's stream is invalid once the request finishes, while the import runs after the response
        var buffer = new MemoryStream();
        await using (var uploadStream = file.OpenReadStream())
        {
            await uploadStream.CopyToAsync(buffer);
        }

        buffer.Position = 0;
        var ownerId = this.GetUserId();
        var jobId = await jobStore.CreateAsync(ownerId, ImportStage.Parsing);

        _ = RunImportJobAsync(jobId, buffer, ownerId);

        return Accepted(new ImportJobDto { JobId = jobId });
    }

    /// <summary>
    /// Current status of a started import job.
    /// </summary>
    [HttpGet("tv-time/{jobId:guid}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<ImportJobStatusDto>> GetStatus(Guid jobId)
    {
        var status = await jobStore.GetStatusAsync(jobId, this.GetUserId());
        if (status is null) return NotFound();

        return Ok(new ImportJobStatusDto { Stage = status.Value.Stage, Result = status.Value.Result, ErrorMessage = status.Value.ErrorMessage });
    }

    /// <summary>
    /// Runs the import on its own DI scope, since the request that started it has completed, and its scoped services, its JobStore included, are disposed.
    /// </summary>
    private async Task RunImportJobAsync(Guid jobId, MemoryStream buffer, string ownerId)
    {
        await using (buffer)
        {
            using var scope = scopeFactory.CreateScope();
            var importService = scope.ServiceProvider.GetRequiredService<TvTimeImportService>();
            var scopedJobStore = scope.ServiceProvider.GetRequiredService<JobStore<ImportStage, ImportResultDto>>();

            try
            {
                var result = await importService.ImportAsync(buffer, ownerId, stage => scopedJobStore.UpdateStageAsync(jobId, stage));
                await scopedJobStore.CompleteAsync(jobId, ImportStage.Completed, result);
            }
            catch (Exception ex)
            {
                await scopedJobStore.FailAsync(jobId, ImportStage.Failed, ex.Message);
            }
        }
    }
}
