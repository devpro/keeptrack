using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/health-records")]
public class HealthRecordController(IDtoMapper<HealthRecordDto, HealthRecordModel> mapper, IHealthRecordRepository dataRepository)
    : DataCrudControllerBase<HealthRecordDto, HealthRecordModel>(mapper, dataRepository);
