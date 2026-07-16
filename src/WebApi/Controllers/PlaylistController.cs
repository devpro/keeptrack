using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/playlists")]
public class PlaylistController(IDtoMapper<PlaylistDto, PlaylistModel> mapper, IPlaylistRepository dataRepository)
    : DataCrudControllerBase<PlaylistDto, PlaylistModel>(mapper, dataRepository);
