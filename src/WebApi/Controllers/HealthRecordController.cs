using System.Linq;
using System.Threading.Tasks;
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
    : DataCrudControllerBase<HealthRecordDto, HealthRecordModel>(mapper, dataRepository)
{
    /// <summary>
    /// Specialties and practitioners this account already recorded, for the journal form's suggestions.
    /// Scoped to the caller, so nothing of one account's health is offered to another.
    /// </summary>
    [HttpGet("suggestions")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<HealthRecordSuggestionsDto>> GetSuggestions()
    {
        var ownerId = this.GetUserId();
        var specialties = await dataRepository.FindDistinctSpecialtiesAsync(ownerId);
        var practitioners = await dataRepository.FindDistinctPractitionersAsync(ownerId);
        return Ok(new HealthRecordSuggestionsDto
        {
            Specialties = specialties.ToList(),
            Practitioners = practitioners.ToList()
        });
    }
}
