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
    /// <summary>
    /// Exposes the mapper to subclasses that add their own actions (e.g. a refresh-reference endpoint) -
    /// lets them reuse this instance instead of capturing their own <c>IMapper</c> primary-constructor
    /// parameter as a second field holding the same reference.
    /// </summary>
    protected IMapper Mapper => mapper;

    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<PagedResult<TDto>>> Get([FromQuery] PagedRequest pagedRequest, [FromQuery] TDto input)
    {
        var models = await dataRepository.FindAllAsync(this.GetUserId(),
            pagedRequest.Page,
            pagedRequest.PageSize,
            pagedRequest.Search,
            mapper.Map<TModel>(input));
        return Ok(models.Map(mapper.Map<TDto>));
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

        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
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
        input.OwnerId = this.GetUserId();
        var model = await dataRepository.CreateAsync(input);
        await OnCreatedAsync(model);
        return CreatedAtAction(nameof(GetById), new { id = model.Id }, mapper.Map<TDto>(model));
    }

    /// <summary>
    /// Hook for subclasses that need to react to a new item being created (e.g. triggering background
    /// reference-data enrichment). No-op by default.
    /// </summary>
    protected virtual Task OnCreatedAsync(TModel model) => Task.CompletedTask;

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
        input.OwnerId = this.GetUserId();
        await dataRepository.UpdateAsync(id, input, this.GetUserId());
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

        await dataRepository.DeleteAsync(id, this.GetUserId());
        return NoContent();
    }
}
