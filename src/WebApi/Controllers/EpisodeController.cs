using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/episodes")]
public class EpisodeController(IMapper mapper, IEpisodeRepository dataRepository)
    : DataCrudControllerBase<EpisodeDto, EpisodeModel>(mapper, dataRepository);
