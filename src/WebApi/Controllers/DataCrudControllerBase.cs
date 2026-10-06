using System.Threading;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The owner-scoped CRUD surface every user-owned collection shares.
/// </summary>
/// <typeparam name="TDto">Data Transfer Object</typeparam>
/// <typeparam name="TModel">Domain Model</typeparam>
[ApiController]
public abstract class DataCrudControllerBase<TDto, TModel>(IDtoMapper<TDto, TModel> mapper, IDataRepository<TModel> dataRepository)
    : ControllerBase
    where TModel : class, IHasIdAndOwnerId
{
    /// <summary>
    /// The mapper, for subclasses adding their own actions, so they reuse this instance rather than capturing the primary-constructor parameter a second time.
    /// </summary>
    protected IDtoMapper<TDto, TModel> Mapper => mapper;

    /// <summary>
    /// How many items a free preview account may create in this collection, as a multiple of <c>Features:FreeTierItemLimit</c>.
    /// Zero, the default, runs no check, which is only right for a controller requiring the "MemberOnly" policy, so a free-tier controller overrides it (<c>MovieController</c>).
    /// </summary>
    protected virtual int FreeTierLimitFactor => 0;

    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<PagedResult<TDto>>> Get([FromQuery] PagedRequest pagedRequest, [FromQuery] TDto input, CancellationToken cancellationToken = default)
    {
        var models = await dataRepository.FindAllAsync(this.GetUserId(),
            pagedRequest.Page,
            pagedRequest.PageSize,
            pagedRequest.Search,
            mapper.ToModel(input),
            pagedRequest.Sort,
            cancellationToken);
        var page = models.Map(mapper.ToDto);
        await OnListMappedAsync(page.Items, cancellationToken);
        return Ok(page);
    }

    /// <summary>
    /// Hook enriching a mapped list page before it is returned, such as hydrating covers (<see cref="ReferenceImageHydrator"/>).
    /// </summary>
    protected virtual Task OnListMappedAsync(List<TDto> dtos, CancellationToken cancellationToken) => Task.CompletedTask;

    [HttpGet("{id}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<TDto>> GetById(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model == null)
        {
            return NotFound();
        }

        return Ok(mapper.ToDto(model));
    }

    [HttpPost]
    [Consumes("application/json", "text/json")]
    [Produces("application/json")]
    [ProducesResponseType(201)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Post([FromBody] TDto dto, CancellationToken cancellationToken = default)
    {
        // the free-tier quota, shared with every other creation path (see FreeTierQuota)
        var quotaError = await FreeTierQuota.CheckAsync(this, FreeTierLimitFactor, () => dataRepository.CountAsync(this.GetUserId(), cancellationToken));
        if (quotaError is not null)
        {
            // same { error } body shape as ApiExceptionFilterAttribute, so clients parse one format
            return StatusCode(StatusCodes.Status403Forbidden, new { error = quotaError });
        }

        var input = mapper.ToModel(dto);
        input.OwnerId = this.GetUserId();
        var model = await dataRepository.CreateAsync(input, cancellationToken);
        await OnCreatedAsync(model);
        return CreatedAtAction(nameof(GetById), new { id = model.Id }, mapper.ToDto(model));
    }

    /// <summary>
    /// Hook reacting to a created item, such as starting background reference resolution.
    /// </summary>
    /// <remarks>
    /// It takes no <see cref="CancellationToken"/>: an override starts detached background work on its own scope, which must outlive the request and never be cancelled because the response was sent.
    /// </remarks>
    protected virtual Task OnCreatedAsync(TModel model) => Task.CompletedTask;

    [HttpPut("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Put(string id, [FromBody] TDto dto, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var input = mapper.ToModel(dto);
        input.OwnerId = this.GetUserId();
        await PreserveServerOwnedFieldsAsync(id, input, cancellationToken);
        await dataRepository.UpdateAsync(id, input, this.GetUserId(), cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Restores the fields the server owns onto <paramref name="input"/>, so an ordinary update can never write them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An update replaces the whole document, so every field the client sent wins, including ones it may not set.
    /// <c>OwnerId</c> is overwritten from the caller's claims above, and the reference link is the other such field.
    /// <b>A record update never changes an item's reference link.</b>
    /// </para>
    /// <para>
    /// The detail page sends the whole DTO on every edit, with a copy fetched as the page opened, before background resolution linked a new item.
    /// Its first edit would write that empty link back over the real one, silently, since nothing on the page changes.
    /// </para>
    /// <para>
    /// It costs one read per update, for the five reference-linked types only.
    /// </para>
    /// </remarks>
    private async Task PreserveServerOwnedFieldsAsync(string id, TModel input, CancellationToken cancellationToken)
    {
        if (input is not IReferenceLinkedModel incoming) return;

        if (await dataRepository.FindOneAsync(id, input.OwnerId, cancellationToken) is not IReferenceLinkedModel stored) return;

        incoming.ReferenceId = stored.ReferenceId;
        incoming.ReferenceRating = stored.ReferenceRating;
        incoming.ReferenceRatingScale = stored.ReferenceRatingScale;
        incoming.ReferenceRatingSource = stored.ReferenceRatingSource;
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Delete(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var ownerId = this.GetUserId();
        await dataRepository.DeleteAsync(id, ownerId, cancellationToken);
        await OnDeletedAsync(id, ownerId, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Hook reacting to a deleted item, such as cascading to a child collection.
    /// Unlike <see cref="OnCreatedAsync"/>, it is awaited within the request, so it takes the request's <see cref="CancellationToken"/>.
    /// </summary>
    protected virtual Task OnDeletedAsync(string id, string ownerId, CancellationToken cancellationToken) => Task.CompletedTask;
}
