using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/gear")]
public class GearController(IDtoMapper<GearDto, GearModel> mapper, IGearRepository dataRepository)
    : DataCrudControllerBase<GearDto, GearModel>(mapper, dataRepository)
{
    /// <summary>
    /// Distinct categories already used across this tenant's gear - feeds the list page's category
    /// filter buttons and the detail page's suggested values. See
    /// <see cref="IGearRepository.FindDistinctCategoriesAsync"/>.
    /// </summary>
    [HttpGet("categories")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<IReadOnlyList<string>>> GetCategories()
    {
        var categories = await dataRepository.FindDistinctCategoriesAsync(this.GetUserId());
        return Ok(categories);
    }
}
