using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The shared, owner-less fuel-station catalogue. Not a <see cref="DataCrudControllerBase{TDto, TModel}"/>:
/// that base scopes every query to the caller and stamps an <c>OwnerId</c>, which is exactly what this
/// collection deliberately doesn't have (see <see cref="CarStationModel"/>).
/// </summary>
/// <remarks>
/// Reads and creation are open to any member, curation is admin-only. A member refuelling somewhere new
/// must never be blocked waiting on an admin, so the picker creates the station on the spot with just a
/// brand name; enriching it with a city and coordinates, merging the near-duplicates that inevitably
/// produces, and deleting are the admin half - the same "act on what's confident, leave the rest for a
/// human" split as reference auto-resolution and its admin queue.
/// </remarks>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/car-stations")]
public class CarStationController(
    IDtoMapper<CarStationDto, CarStationModel> mapper,
    ICarStationRepository stationRepository,
    ICarHistoryRepository carHistoryRepository)
    : ControllerBase
{
    /// <summary>
    /// The whole catalogue, ordered by brand then city - what the car history form's station picker offers.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<CarStationDto>>> Get()
    {
        var stations = await stationRepository.FindAllAsync();
        return Ok(stations.Select(mapper.ToDto).ToList());
    }

    /// <summary>
    /// The catalogue with each station's usage count, for the admin management screen.
    /// </summary>
    [HttpGet("admin")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<CarStationDto>>> GetForAdmin()
    {
        var stations = await stationRepository.FindAllAsync();
        // one grouped aggregation for the whole page, not a count per row
        var usageByStationId = await carHistoryRepository.CountByStationAsync();
        var dtos = stations.Select(station =>
        {
            var dto = mapper.ToDto(station);
            dto.UsageCount = dto.Id is not null && usageByStationId.TryGetValue(dto.Id, out var count) ? count : 0;
            return dto;
        }).ToList();
        return Ok(dtos);
    }

    [HttpGet("{id}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<CarStationDto>> GetById(string id)
    {
        if (string.IsNullOrEmpty(id)) return BadRequest();
        var station = await stationRepository.FindByIdAsync(id);
        return station is null ? NotFound() : Ok(mapper.ToDto(station));
    }

    /// <summary>
    /// Find-or-create by natural key (normalized brand name + city + postal code). Idempotent on purpose:
    /// the picker posts here every time a member types a station that isn't in the list yet, and two members
    /// typing "Total" at the same address must land on one document, not two.
    /// </summary>
    [HttpPost]
    [Consumes("application/json", "text/json")]
    [Produces("application/json")]
    [ProducesResponseType(200)]
    [ProducesResponseType(201)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<CarStationDto>> Post([FromBody] CarStationDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.BrandName))
        {
            return BadRequest(new { error = "A station needs a brand name." });
        }

        var existing = await stationRepository.FindByNaturalKeyAsync(dto.BrandName, dto.City, dto.PostalCode);
        if (existing is not null)
        {
            return Ok(mapper.ToDto(existing));
        }

        var model = mapper.ToModel(dto);
        model.Id = null;
        var created = await stationRepository.UpsertAsync(model);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, mapper.ToDto(created));
    }

    /// <summary>
    /// Admin-only: enrich a station with its city, postal code, country and coordinates.
    /// </summary>
    [HttpPut("{id}")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(409)]
    public async Task<IActionResult> Put(string id, [FromBody] CarStationDto dto)
    {
        if (string.IsNullOrEmpty(id)) return BadRequest();
        if (string.IsNullOrWhiteSpace(dto.BrandName))
        {
            return BadRequest(new { error = "A station needs a brand name." });
        }

        var existing = await stationRepository.FindByIdAsync(id);
        if (existing is null) return NotFound();

        // An edit can move a station onto another one's natural key ("Total" gaining the city that makes it
        // the "Total - Rennes" already on file). The unique index would reject that write outright, so name
        // the conflict instead - "merge these two" is an action the admin has, a duplicate-key 500 is not.
        var clash = await stationRepository.FindByNaturalKeyAsync(dto.BrandName, dto.City, dto.PostalCode);
        if (clash is not null && clash.Id != id)
        {
            return Conflict(new { error = $"Another station already covers \"{dto.BrandName}\" in that city - merge them instead." });
        }

        var model = mapper.ToModel(dto);
        model.Id = id;
        await stationRepository.UpsertAsync(model);
        return NoContent();
    }

    /// <summary>
    /// Admin-only: delete a station no entry points at. A station is only ever reachable through an entry's
    /// <c>StationId</c>, so deleting one still in use would blank the location of every refuel referencing
    /// it with nothing to recover it from - that's a merge, not a delete.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(409)]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id)) return BadRequest();

        var usageCount = await carHistoryRepository.CountUsingStationAsync(id);
        if (usageCount > 0)
        {
            return Conflict(new { error = $"{usageCount} history entr{(usageCount == 1 ? "y" : "ies")} still use this station - merge it into another one instead." });
        }

        return await stationRepository.DeleteAsync(id) ? NoContent() : NotFound();
    }

    /// <summary>
    /// Admin-only: fold <paramref name="id"/> into <paramref name="targetId"/>, re-pointing every entry
    /// first and only then deleting the absorbed document - the same ordering and the same reason as the
    /// video-game reference merge: skipping the re-point silently blanks those entries' station.
    /// </summary>
    [HttpPost("{id}/merge/{targetId}")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<CarStationMergeResultDto>> Merge(string id, string targetId)
    {
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(targetId)) return BadRequest();
        if (id == targetId) return BadRequest(new { error = "A station cannot be merged into itself." });

        var absorbed = await stationRepository.FindByIdAsync(id);
        var survivor = await stationRepository.FindByIdAsync(targetId);
        if (absorbed is null || survivor is null) return NotFound();

        // The survivor keeps everything it already knows and only gains what it is missing - both documents
        // describe the same physical station, so a field only one of them has is strictly new information.
        // Same "never overwrite with nothing" rule as SetReferenceLinkAsync.
        survivor.PostalCode ??= absorbed.PostalCode;
        survivor.Country ??= absorbed.Country;
        survivor.Longitude ??= absorbed.Longitude;
        survivor.Latitude ??= absorbed.Latitude;

        // The city is part of the natural key, so adopting it can move the survivor onto a *third*
        // station's key, which the unique index rejects outright. Gaining a city is a cosmetic improvement
        // and losing the merge is not, so the adoption is checked and skipped rather than attempted.
        if (survivor.City is null && absorbed.City is not null)
        {
            var clash = await stationRepository.FindByNaturalKeyAsync(survivor.BrandName, absorbed.City, survivor.PostalCode);
            if (clash is null || clash.Id == id) survivor.City = absorbed.City;
        }

        // Re-point before deleting: while both documents exist the entries can be moved, and an entry left
        // pointing at a deleted station renders as no station at all with nothing to recover it from.
        var repointed = await carHistoryRepository.RepointStationAsync(id, targetId);
        await stationRepository.DeleteAsync(id);
        await stationRepository.UpsertAsync(survivor);

        return Ok(new CarStationMergeResultDto { RepointedEntries = repointed, Station = mapper.ToDto(survivor) });
    }
}
