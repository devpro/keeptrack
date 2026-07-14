using Keeptrack.WebApi.Controllers;
using Keeptrack.WebApi.Jobs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
[Authorize]
[Route("api/import")]
public class TvTimeImportController(JobStore<ImportStage, ImportResultDto> jobStore, IServiceScopeFactory scopeFactory) : ControllerBase
{
    /// <summary>
    /// Starts importing a TV Time GDPR export (the zip you get from TV Time's "Download my data" request)
    /// as an upsert. Runs in the background; poll <see cref="GetStatus"/> with the returned job id for progress.
    /// </summary>
    [HttpPost("tv-time")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(202)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<ImportJobDto>> ImportTvTime(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        // buffered up front: IFormFile's stream isn't valid once this request finishes, but the import
        // itself runs in the background after we respond
        var buffer = new MemoryStream();
        await using (var uploadStream = file.OpenReadStream())
        {
            await uploadStream.CopyToAsync(buffer);
        }

        buffer.Position = 0;
        var ownerId = this.GetUserId();
        var jobId = jobStore.Create(ownerId, ImportStage.Parsing);

        _ = RunImportJobAsync(jobId, buffer, ownerId);

        return Accepted(new ImportJobDto { JobId = jobId });
    }

    /// <summary>
    /// Current status of a previously started import job.
    /// </summary>
    [HttpGet("tv-time/{jobId:guid}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public ActionResult<ImportJobStatusDto> GetStatus(Guid jobId)
    {
        var status = jobStore.GetStatus(jobId, this.GetUserId());
        if (status is null) return NotFound();

        return Ok(new ImportJobStatusDto { Stage = status.Value.Stage, Result = status.Value.Result, ErrorMessage = status.Value.ErrorMessage });
    }

    /// <summary>
    /// Runs the import on a background task using its own DI scope (the request that started it has
    /// already completed by the time this runs, so it can't reuse the request's scoped services).
    /// </summary>
    private async Task RunImportJobAsync(Guid jobId, MemoryStream buffer, string ownerId)
    {
        await using (buffer)
        {
            using var scope = scopeFactory.CreateScope();
            var importService = scope.ServiceProvider.GetRequiredService<TvTimeImportService>();

            try
            {
                var result = await importService.ImportAsync(buffer, ownerId, stage => jobStore.UpdateStage(jobId, stage));
                jobStore.Complete(jobId, ImportStage.Completed, result);
            }
            catch (Exception ex)
            {
                jobStore.Fail(jobId, ImportStage.Failed, ex.Message);
            }
        }
    }
}
