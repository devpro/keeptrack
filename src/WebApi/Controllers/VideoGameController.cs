using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/video-games")]
public class VideoGameController(
    IDtoMapper<VideoGameDto, VideoGameModel> mapper,
    IVideoGameRepository dataRepository,
    IVideoGameReferenceRepository referenceRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<VideoGameController> logger)
    : DataCrudControllerBase<VideoGameDto, VideoGameModel>(mapper, dataRepository)
{
    /// <summary>
    /// Hydrates each page item's cover image from its linked reference document - one batched lookup per
    /// page (see <see cref="ReferenceImageHydrator"/>), keyed by the id-bearing documents only. A game with
    /// its own <see cref="VideoGameDto.CustomImageUrl"/> set overrides that afterward - see
    /// <see cref="BookController.OnListMappedAsync"/>.
    /// </summary>
    protected override async Task OnListMappedAsync(List<VideoGameDto> dtos)
    {
        await ReferenceImageHydrator.HydrateAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl);
        foreach (var dto in dtos.Where(d => !string.IsNullOrEmpty(d.CustomImageUrl)))
        {
            dto.ImageUrl = dto.CustomImageUrl;
        }
    }

    /// <summary>
    /// Fires a best-effort background RAWG match for the new game - see <see cref="TvShowController.OnCreatedAsync"/>.
    /// </summary>
    protected override Task OnCreatedAsync(VideoGameModel model)
    {
        var title = model.Title;
        var year = model.Year;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveVideoGameAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for video game '{Title}'.", title);
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
    public async Task<ActionResult<VideoGameDto>> RefreshReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.TryLinkExistingVideoGameReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Admin-only: clears this game's reference link and permanently deletes the shared reference
    /// document - see <see cref="TvShowController.UnlinkReference"/>.
    /// </summary>
    [HttpPost("{id}/unlink-reference")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<VideoGameDto>> UnlinkReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.UnlinkVideoGameReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
