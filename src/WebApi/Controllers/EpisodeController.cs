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
    /// Episodes ride along with the free tier's TV shows, so the cap is deliberately generous (100x the
    /// per-collection limit): ticking off a full watch-through is the product's core value and must never
    /// feel rationed - the cap only exists so an anonymous-signup account can't flood the database
    /// through the raw API.
    /// </summary>
    protected override int FreeTierLimitFactor => 100;
}
