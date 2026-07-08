using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/songs")]
public class SongController(IMapper mapper, ISongRepository dataRepository)
    : DataCrudControllerBase<SongDto, SongModel>(mapper, dataRepository);
