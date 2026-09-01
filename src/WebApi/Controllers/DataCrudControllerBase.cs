using System.Threading;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Data CRUD (Create, Request, Update, Delete) Controller abstract class.
/// </summary>
/// <typeparam name="TDto">Data Transfer Object</typeparam>
/// <typeparam name="TModel">Domain Model</typeparam>
[ApiController]
public abstract class DataCrudControllerBase<TDto, TModel>(IDtoMapper<TDto, TModel> mapper, IDataRepository<TModel> dataRepository)
    : ControllerBase
    where TModel : class, IHasIdAndOwnerId
{
    /// <summary>
    /// Exposes the mapper to subclasses that add their own actions (e.g. a refresh-reference endpoint) -
    /// lets them reuse this instance instead of capturing their own <c>IDtoMapper</c> primary-constructor
    /// parameter as a second field holding the same reference.
    /// </summary>
    protected IDtoMapper<TDto, TModel> Mapper => mapper;

    /// <summary>
    /// How many items a non-member ("free preview") account may create in this collection, as a multiple
    /// of the configured <c>Features:FreeTierItemLimit</c>. 0 (the default) means no quota check runs
    /// here - which is only correct for controllers whose whole surface already requires the "MemberOnly"
    /// policy; a controller that is part of the free tier must override this (see <c>MovieController</c>).
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
    /// Hook for subclasses that enrich a mapped list page before it is returned (e.g. hydrating
    /// reference-image URLs, see <see cref="ReferenceImageHydrator"/>).
    /// No-op by default.
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
        // free-tier creation quota, shared with the shared-item copy path (see FreeTierQuota)
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
    /// Hook for subclasses that need to react to a new item being created (e.g. triggering background
    /// reference-data enrichment).
    /// No-op by default.
    /// </summary>
    /// <remarks>
    /// Deliberately takes no <see cref="CancellationToken"/>: a subclass override starts detached
    /// background work (its own DI scope, never awaited inline), which must outlive this request and must
    /// never be cancelled just because the HTTP response has already been sent.
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
    /// An update is a full replace of the document, so every field the client sent wins - including ones it was never entitled to set.
    /// <c>OwnerId</c> is already handled that way (overwritten from the caller's claims just above); a reference link is the other case, and it is the one that bit.
    /// <b>A record update must never change an item's reference link. Only the detail page's "check for reference match" does.</b>
    /// </para>
    /// <para>
    /// Without this, the Blazor detail page - which sends the whole DTO on every field edit - erases a link simply by saving something else.
    /// Its copy is fetched the instant the page opens, which for a just-created item is before the background resolution has linked it, so the first edit writes that stale empty link back over the real one.
    /// It cost a long run of "it doesn't match, but if I click refresh it matches" reports: the match had happened, the next edit undid it, and the button resolved it again.
    /// Nothing about the page changes when a save removes a link, which is what kept it invisible.
    /// </para>
    /// <para>
    /// Costs one read per update, and only for the five reference-linked types - everything else fails the type test and pays nothing.
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
    /// Hook for subclasses that need to react to an item being deleted (e.g. cascading the delete to a
    /// child collection such as CarHistory).
    /// No-op by default.
    /// Unlike <see cref="OnCreatedAsync"/>, this one is awaited as part of the same request (a cascade
    /// delete is not detached background work), so it does take the request's <see cref="CancellationToken"/>.
    /// </summary>
    protected virtual Task OnDeletedAsync(string id, string ownerId, CancellationToken cancellationToken) => Task.CompletedTask;
}
