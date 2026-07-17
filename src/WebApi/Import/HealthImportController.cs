using System.Diagnostics.CodeAnalysis;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/import")]
public class HealthImportController(HealthImportService importService) : ControllerBase
{
    /// <summary>
    /// Imports the personal "Journal_sante.xlsx" spreadsheet
    /// (one sheet of health events, every family member mixed in one "Personne" column - profiles are created/matched by name).
    /// Runs synchronously, same as the car import: no external API call in the loop, so a few hundred rows complete well within a normal request.
    /// </summary>
    [HttpPost("health")]
    [RequestSizeLimit(10_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (10 MB), deliberately above Sonar's 8 MB default.")]
    public async Task<ActionResult<HealthImportResultDto>> ImportHealth(IFormFile file)
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
