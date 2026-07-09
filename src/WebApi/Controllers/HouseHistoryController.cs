using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/house-history")]
public class HouseHistoryController(IMapper mapper, IHouseHistoryRepository dataRepository)
    : DataCrudControllerBase<HouseHistoryDto, HouseHistoryModel>(mapper, dataRepository);
