using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Read-only access to the shared reference collection, for any authenticated user (not admin-only).
/// Kept separate from <see cref="Controllers.TvShowController"/>/<see cref="Controllers.MovieController"/>
/// deliberately - this is shared data, not the tenant's own document.
/// </summary>
[ApiController]
[Authorize]
[Route("api/reference-data")]
public class ReferenceDataController(
    IMapper mapper,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository)
    : ControllerBase
{
    [HttpGet("tv-shows/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowReferenceDto>> GetTvShow(string referenceId)
    {
        var model = await tvShowReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = mapper.Map<TvShowReferenceDto>(model);
        dto.Cast = await HydrateCastAsync(model.Cast);
        return Ok(dto);
    }

    [HttpGet("movies/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<MovieReferenceDto>> GetMovie(string referenceId)
    {
        var model = await movieReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = mapper.Map<MovieReferenceDto>(model);
        dto.Cast = await HydrateCastAsync(model.Cast);
        return Ok(dto);
    }

    /// <summary>
    /// Joins the embedded cast list against person_reference to build the fully-hydrated DTO the client
    /// renders directly - see <see cref="Keeptrack.WebApi.MappingProfiles.WebServiceMappingProfile"/> for
    /// why this can't just be an AutoMapper member mapping.
    /// </summary>
    private async Task<List<CastMemberDto>> HydrateCastAsync(List<CastMemberModel> cast)
    {
        var result = new List<CastMemberDto>();
        foreach (var member in cast.OrderBy(c => c.Order))
        {
            var person = await personReferenceRepository.FindByIdAsync(member.PersonReferenceId);
            if (person is null) continue;

            result.Add(new CastMemberDto { Name = person.Name, CharacterName = member.CharacterName, ProfileImageUrl = person.ProfileImageUrl });
        }

        return result;
    }
}
