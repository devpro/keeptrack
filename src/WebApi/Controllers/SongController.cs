using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/songs")]
public class SongController(IDtoMapper<SongDto, SongModel> mapper, ISongRepository dataRepository)
    : DataCrudControllerBase<SongDto, SongModel>(mapper, dataRepository);
