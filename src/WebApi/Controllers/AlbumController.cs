using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/albums")]
public class AlbumController(
    IMapper mapper,
    IAlbumRepository dataRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<AlbumController> logger)
    : DataCrudControllerBase<AlbumDto, AlbumModel>(mapper, dataRepository)
{
    /// <summary>
    /// Fires a best-effort background Discogs match for the new album - see <see cref="TvShowController.OnCreatedAsync"/>.
    /// </summary>
    protected override Task OnCreatedAsync(AlbumModel model)
    {
        var title = model.Title;
        var year = model.Year;
        var artist = model.Artist;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveAlbumAsync(title, year, artist);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for album '{Title}'.", title);
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
    public async Task<ActionResult<AlbumDto>> RefreshReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.TryLinkExistingAlbumReferenceAsync(model);
        return Ok(Mapper.Map<AlbumDto>(model));
    }
}
