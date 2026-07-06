using System.Threading.Tasks;
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
public class ReferenceDataController(IMapper mapper, ITvShowReferenceRepository tvShowReferenceRepository, IMovieReferenceRepository movieReferenceRepository)
    : ControllerBase
{
    [HttpGet("tv-shows/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowReferenceDto>> GetTvShow(string referenceId)
    {
        var model = await tvShowReferenceRepository.FindByIdAsync(referenceId);
        return model is null ? NotFound() : Ok(mapper.Map<TvShowReferenceDto>(model));
    }

    [HttpGet("movies/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<MovieReferenceDto>> GetMovie(string referenceId)
    {
        var model = await movieReferenceRepository.FindByIdAsync(referenceId);
        return model is null ? NotFound() : Ok(mapper.Map<MovieReferenceDto>(model));
    }
}
