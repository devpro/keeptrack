using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/video-games")]
public class VideoGameController(IMapper mapper, IVideoGameRepository dataRepository)
    : DataCrudControllerBase<VideoGameDto, VideoGameModel>(mapper, dataRepository);
