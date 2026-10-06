using System.Threading;
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
    /// Hydrates each item's cover from its linked reference, one batched lookup per page (see <see cref="ReferenceImageHydrator"/>).
    /// A game's own <see cref="VideoGameDto.CustomImageUrl"/> then overrides it (see <see cref="BookController.OnListMappedAsync"/>).
    /// </summary>
    protected override Task OnListMappedAsync(List<VideoGameDto> dtos, CancellationToken cancellationToken) =>
        ReferenceImageHydrator.HydrateWithCustomOverrideAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl, x => x.CustomImageUrl);

    /// <summary>
    /// Starts a best-effort background match through the default game provider (see <see cref="TvShowController.OnCreatedAsync"/>).
    /// </summary>
    protected override Task OnCreatedAsync(VideoGameModel model)
    {
        var title = model.Title;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveVideoGameAsync(model);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for video game '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// "Check for reference match" (see <see cref="TvShowController.RefreshReference"/>).
    /// A game created before its year was known links once the year is filled in (see <see cref="ReferenceEnrichmentService.LinkVideoGameReferenceAsync"/>).
    /// </summary>
    [HttpPost("{id}/refresh-reference")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<VideoGameDto>> RefreshReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.LinkVideoGameReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Admin only: clears this game's link and deletes the shared reference document (see <see cref="TvShowController.UnlinkReference"/>).
    /// </summary>
    [HttpPost("{id}/unlink-reference")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<VideoGameDto>> UnlinkReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.UnlinkVideoGameReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
