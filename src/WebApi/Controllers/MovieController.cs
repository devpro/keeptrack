using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/movies")]
public class MovieController(IMapper mapper, IMovieRepository dataRepository)
    : DataCrudControllerBase<MovieDto, MovieModel>(mapper, dataRepository);
