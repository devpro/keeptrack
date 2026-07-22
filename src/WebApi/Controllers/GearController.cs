using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/gear")]
public class GearController(IDtoMapper<GearDto, GearModel> mapper, IGearRepository dataRepository)
    : DataCrudControllerBase<GearDto, GearModel>(mapper, dataRepository);
