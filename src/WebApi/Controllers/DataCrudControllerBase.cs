using Keeptrack.Common.System;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Data CRUD (Create, Request, Update, Delete) Controller abstract class.
/// </summary>
/// <typeparam name="TDto">Data Transfer Object</typeparam>
/// <typeparam name="TModel">Domain Model</typeparam>
[ApiController]
public abstract class DataCrudControllerBase<TDto, TModel>(IMapper mapper, IDataRepository<TModel> dataRepository)
    : ControllerBase
    where TModel : class, IHasIdAndOwnerId
{
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<PagedResult<TDto>>> Get([FromQuery] PagedRequest pagedRequest, [FromQuery] TDto input)
    {
        var models = await dataRepository.FindAllAsync(GetUserId(),
            pagedRequest.Page,
            pagedRequest.PageSize,
            pagedRequest.Search,
            mapper.Map<TModel>(input));
        return Ok(models.Map(model => mapper.Map<TDto>(model)));
    }

    [HttpGet("{id}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<TDto>> GetById(string id)
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

        return Ok(mapper.Map<TDto>(model));
    }

    [HttpPost]
    [Consumes("application/json", "text/json")]
    [Produces("application/json")]
    [ProducesResponseType(201)]
    public async Task<IActionResult> Post([FromBody] TDto dto)
    {
        var input = mapper.Map<TModel>(dto);
        input.OwnerId = GetUserId();
        var model = await dataRepository.CreateAsync(input);
        return CreatedAtAction(nameof(GetById), new { id = model.Id }, mapper.Map<TDto>(model));
    }

    [HttpPut("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Put(string id, [FromBody] TDto dto)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var input = mapper.Map<TModel>(dto);
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
