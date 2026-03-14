using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/music-albums")]
public class MusicAlbumController(IMapper mapper, IMusicAlbumRepository dataRepository)
    : DataCrudControllerBase<MusicAlbumDto, MusicAlbumModel>(mapper, dataRepository);
