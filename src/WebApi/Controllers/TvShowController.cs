using System.Threading;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/tv-shows")]
public class TvShowController(
    IDtoMapper<TvShowDto, TvShowModel> mapper,
    ITvShowRepository dataRepository,
    ITvShowReferenceRepository referenceRepository,
    IEpisodeRepository episodeRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<TvShowController> logger)
    : DataCrudControllerBase<TvShowDto, TvShowModel>(mapper, dataRepository)
{
    /// <summary>TV shows are in the free preview tier, capped at the configured limit for non-members.</summary>
    protected override int FreeTierLimitFactor => 1;

    /// <summary>
    /// Hydrates each item's cover from its linked reference, one batched lookup per page (see <see cref="ReferenceImageHydrator"/>).
    /// </summary>
    protected override Task OnListMappedAsync(List<TvShowDto> dtos, CancellationToken cancellationToken)
        => ReferenceImageHydrator.HydrateAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl);

    /// <summary>
    /// Starts a best-effort background TMDB match for the new show, on its own DI scope, since the request completes before it does.
    /// </summary>
    protected override Task OnCreatedAsync(TvShowModel model)
    {
        var title = model.Title;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveTvShowAsync(model);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for TV show '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// "Check for reference match", open to every user: the local references first, then the provider under the same rules as automatic resolution.
    /// It links this item only, after the tenant corrected its title or year (see docs/reference-data.md).
    /// </summary>
    [HttpPost("{id}/refresh-reference")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowDto>> RefreshReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.LinkTvShowReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Admin only: clears this show's link and deletes the shared reference document, since the admin found the match wrong, so the document is bad data.
    /// It changes data other tenants may point at, so a method-level policy adds the admin gate to the controller's plain <c>[Authorize]</c>.
    /// Clearing <c>ReferenceId</c> brings back the detail page's <c>InlineReferenceLinker</c>, so the admin picks the right match at once.
    /// </summary>
    [HttpPost("{id}/unlink-reference")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowDto>> UnlinkReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.UnlinkTvShowReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Cascades to the show's episodes, a separate collection reachable only through the show's id, which would otherwise be orphaned forever.
    /// </summary>
    protected override async Task OnDeletedAsync(string id, string ownerId, CancellationToken cancellationToken)
    {
        await episodeRepository.DeleteAllForShowAsync(id, ownerId, cancellationToken);
    }
}
