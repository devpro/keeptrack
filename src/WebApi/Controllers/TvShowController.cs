using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/tv-shows")]
public class TvShowController(IMapper mapper, ITvShowRepository dataRepository)
    : DataCrudControllerBase<TvShowDto, TvShowModel>(mapper, dataRepository);
