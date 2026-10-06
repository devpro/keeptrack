using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The caller's opt-in toggles, one resource per owner with no id in the route, so a plain <see cref="ControllerBase"/>.
/// Open to every authenticated user, since these are UI preferences.
/// </summary>
[ApiController]
[Authorize]
[Route("api/user-preferences")]
public class UserPreferencesController(IUserPreferencesRepository repository, IDtoMapper<UserPreferencesDto, UserPreferencesModel> mapper) : ControllerBase
{
    /// <summary>
    /// The caller's preferences, all off when nothing was saved yet.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<UserPreferencesDto>> Get()
    {
        var ownerId = this.GetUserId();
        var model = await repository.FindByOwnerIdAsync(ownerId) ?? new UserPreferencesModel { OwnerId = ownerId };
        return Ok(mapper.ToDto(model));
    }

    /// <summary>
    /// Replaces the caller's preferences.
    /// </summary>
    [HttpPut]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Put(UserPreferencesDto dto)
    {
        var ownerId = this.GetUserId();
        var model = mapper.ToModel(dto);
        model.OwnerId = ownerId;
        await repository.UpsertAsync(model);
        return NoContent();
    }
}
