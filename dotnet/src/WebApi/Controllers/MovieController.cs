using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/movies")]
public class MovieController(IMapper mapper, IMovieRepository dataRepository)
    : DataCrudControllerBase<MovieDto, MovieModel>(mapper, dataRepository);
