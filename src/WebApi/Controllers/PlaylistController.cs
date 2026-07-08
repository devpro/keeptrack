using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/playlists")]
public class PlaylistController(IMapper mapper, IPlaylistRepository dataRepository)
    : DataCrudControllerBase<PlaylistDto, PlaylistModel>(mapper, dataRepository);
