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
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<TvShowController> logger)
    : DataCrudControllerBase<TvShowDto, TvShowModel>(mapper, dataRepository)
{
    /// <summary>TV shows are part of the free preview tier, capped at the configured limit for non-members.</summary>
    protected override int FreeTierLimitFactor => 1;

    /// <summary>
    /// Hydrates each page item's cover image from its linked reference document - one batched lookup per
    /// page (see <see cref="ReferenceImageHydrator"/>), keyed by the id-bearing documents only.
    /// </summary>
    protected override Task OnListMappedAsync(List<TvShowDto> dtos)
        => ReferenceImageHydrator.HydrateAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl);

    /// <summary>
    /// Fires a best-effort background TMDB match for the new show. Runs on its own DI scope since the
    /// request will have completed by the time it finishes - same shape as the TV Time import job.
    /// </summary>
    protected override Task OnCreatedAsync(TvShowModel model)
    {
        var title = model.Title;
        var year = model.Year;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveTvShowAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for TV show '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection - no TMDB call.
    /// Distinct from the admin-only live TMDB search/linker: this only ever picks up a match that already
    /// exists locally (e.g. after the tenant fixes a typo'd title), so any user can trigger it.
    /// </summary>
    [HttpPost("{id}/refresh-reference")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowDto>> RefreshReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.TryLinkExistingTvShowReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
