using System.Diagnostics.CodeAnalysis;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
// MemberOnly like CarController itself: this import creates cars/history through the repositories,
// which would otherwise let a free-preview account bypass the controller-level policy entirely
[Authorize(Policy = "MemberOnly")]
[Route("api/import")]
public class CarHistoryImportController(CarHistoryImportService importService) : ControllerBase
{
    /// <summary>
    /// Imports the personal "Voitures.xlsx" spreadsheet (fuel/maintenance history per car).
    /// Runs synchronously - unlike the TV Time import, there's no external API call in the loop, so a few hundred rows complete well within a normal request.
    /// </summary>
    [HttpPost("car-history")]
    [RequestSizeLimit(10_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [SuppressMessage("Security", "S5693:Make sure the content length limit is safe here",
        Justification = "The limit IS set (10 MB), deliberately above Sonar's 8 MB default.")]
    public async Task<ActionResult<CarHistoryImportResultDto>> ImportCarHistory(IFormFile file)
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
