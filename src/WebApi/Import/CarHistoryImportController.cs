using System.IO;
using System.Threading.Tasks;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Import;

[ApiController]
[Authorize]
[Route("api/import")]
public class CarHistoryImportController(CarHistoryImportService importService) : ControllerBase
{
    /// <summary>
    /// Imports the personal "Voitures.xlsx" spreadsheet (fuel/maintenance history per car). Runs
    /// synchronously - unlike the TV Time import, there's no external API call in the loop, so a few
    /// hundred rows complete well within a normal request.
    /// </summary>
    [HttpPost("car-history")]
    [RequestSizeLimit(10_000_000)]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
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
