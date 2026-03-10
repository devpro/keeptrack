using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/car-history")]
public class CarHistoryController(IMapper mapper, ICarHistoryRepository dataRepository)
    : DataCrudControllerBase<CarHistoryDto, CarHistoryModel>(mapper, dataRepository);
