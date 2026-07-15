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
    /// <summary>
    /// Hydrates each page item's cover image from its linked reference document - one batched lookup per
    /// page (see <see cref="ReferenceImageHydrator"/>), keyed by the id-bearing documents only.
    /// </summary>
    protected override async Task OnListMappedAsync(List<MovieDto> dtos)
    {
        var references = await referenceRepository.FindByIdsAsync(ReferenceImageHydrator.CollectReferenceIds(dtos));
        ReferenceImageHydrator.Apply(dtos, references.Where(x => x.Id is not null).ToDictionary(x => x.Id!, x => x.ImageUrl));
    }

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
}
