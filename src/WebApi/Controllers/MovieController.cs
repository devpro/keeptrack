using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/movies")]
public class MovieController(
    IDtoMapper<MovieDto, MovieModel> mapper,
    IMovieRepository dataRepository,
    IMovieReferenceRepository referenceRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<MovieController> logger)
    : DataCrudControllerBase<MovieDto, MovieModel>(mapper, dataRepository)
{
    /// <summary>Movies are part of the free preview tier, capped at the configured limit for non-members.</summary>
    protected override int FreeTierLimitFactor => 1;

    /// <summary>
    /// Hydrates each page item's cover image from its linked reference document - one batched lookup per
    /// page (see <see cref="ReferenceImageHydrator"/>), keyed by the id-bearing documents only.
    /// </summary>
    protected override Task OnListMappedAsync(List<MovieDto> dtos)
        => ReferenceImageHydrator.HydrateAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl);

    /// <summary>
    /// Fires a best-effort background TMDB match for the new movie - see <see cref="TvShowController.OnCreatedAsync"/>.
    /// </summary>
    protected override Task OnCreatedAsync(MovieModel model)
    {
        var title = model.Title;
        var year = model.Year;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveMovieAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for movie '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection - see
    /// <see cref="TvShowController.RefreshReference"/>.
    /// </summary>
    [HttpPost("{id}/refresh-reference")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<MovieDto>> RefreshReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.TryLinkExistingMovieReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Admin-only: clears this movie's reference link and permanently deletes the shared reference
    /// document - see <see cref="TvShowController.UnlinkReference"/>.
    /// </summary>
    [HttpPost("{id}/unlink-reference")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<MovieDto>> UnlinkReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.UnlinkMovieReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
