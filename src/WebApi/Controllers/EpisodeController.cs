using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/episodes")]
public class EpisodeController(IDtoMapper<EpisodeDto, EpisodeModel> mapper, IEpisodeRepository dataRepository)
    : DataCrudControllerBase<EpisodeDto, EpisodeModel>(mapper, dataRepository)
{
    /// <summary>
    /// Episodes come with the free tier's TV shows, so the cap is generous, 100 times the collection limit, since ticking off a whole watch-through must never feel rationed.
    /// It only stops an account flooding the database through the raw API.
    /// </summary>
    protected override int FreeTierLimitFactor => 100;
}
