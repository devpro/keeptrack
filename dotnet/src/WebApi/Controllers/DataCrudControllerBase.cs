using KeepTrack.Api.Dto.Queries;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

/// <summary>
/// Data CRUD (Create, Request, Update, Delete) Controller abstract class.
/// </summary>
/// <typeparam name="T">Data Transfer Object</typeparam>
/// <typeparam name="U">Domain Model</typeparam>
public abstract class DataCrudControllerBase<T, U>(IMapper mapper, IDataRepository<U> dataRepository)
    : ControllerBase
    where U : Domain.Models.IDataModel
{
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<List<T>>> Get([FromQuery] DataQuery dataQuery, [FromQuery] T input)
    {
        var models = await dataRepository.FindAllAsync(GetUserId(), dataQuery.Page, dataQuery.PageSize, dataQuery.Search, mapper.Map<U>(input));
        return Ok(mapper.Map<List<T>>(models));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<T>> GetById(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var model = await dataRepository.FindOneAsync(id, GetUserId());
        if (model == null)
        {
            return NotFound();
        }

        return Ok(mapper.Map<T>(model));
    }

    [HttpPost]
    [ProducesResponseType(201)]
    public async Task<IActionResult> Post([FromBody] T dto)
    {
        var input = mapper.Map<U>(dto);
        input.OwnerId = GetUserId();
        var model = await dataRepository.CreateAsync(input);
        return CreatedAtAction(nameof(GetById), new { id = model.Id }, mapper.Map<T>(model));
    }

    [HttpPut("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Put(string id, [FromBody] T dto)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var input = mapper.Map<U>(dto);
        input.OwnerId = GetUserId();
        await dataRepository.UpdateAsync(id, input, GetUserId());
        return NoContent();
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        await dataRepository.DeleteAsync(id, GetUserId());
        return NoContent();
    }

    /// <summary>
    /// Get authenticated user id.
    /// </summary>
    /// <returns></returns>
    private string GetUserId()
    {
        var userId = User.Claims.FirstOrDefault(x => x.Type == "user_id")?.Value;
        return string.IsNullOrEmpty(userId) ? throw new UnauthorizedAccessException() : userId;
    }
}
