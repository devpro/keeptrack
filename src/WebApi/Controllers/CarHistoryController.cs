using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/car-history")]
public class CarHistoryController(IMapper mapper, ICarHistoryRepository dataRepository)
    : DataCrudControllerBase<CarHistoryDto, CarHistoryModel>(mapper, dataRepository);
