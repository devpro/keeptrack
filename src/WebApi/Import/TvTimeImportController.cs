using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
[Authorize]
[Route("api/import")]
public class TvTimeImportController(TvTimeImportService importService) : ControllerBase
{
    /// <summary>
    /// Imports a TV Time GDPR export (the zip you get from TV Time's "Download my data" request) as an upsert.
    /// </summary>
    [HttpPost("tv-time")]
    [RequestSizeLimit(50_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<ImportResultDto>> ImportTvTime(IFormFile file)
    {
        if (file.Length == 0)
        {
            return BadRequest();
        }

        await using var stream = file.OpenReadStream();
        var result = await importService.ImportAsync(stream, this.GetUserId());
        return Ok(result);
    }
}
