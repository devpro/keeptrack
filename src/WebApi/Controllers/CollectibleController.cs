using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/collectibles")]
public class CollectibleController(IDtoMapper<CollectibleDto, CollectibleModel> mapper, ICollectibleRepository dataRepository)
    : DataCrudControllerBase<CollectibleDto, CollectibleModel>(mapper, dataRepository);
