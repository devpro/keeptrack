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
    /// Specialties and practitioners this account has already recorded, feeding the journal form's
    /// suggestion dropdowns - the same "suggest what you've already typed" shape as
    /// <c>GearController.GetCategories</c> and <c>CarHistoryController.GetFuelCategories</c>, scoped to the
    /// caller so nothing about one account's health is ever offered to another.
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
