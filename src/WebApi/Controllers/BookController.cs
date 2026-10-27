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
[Route("api/books")]
public class BookController(
    IDtoMapper<BookDto, BookModel> mapper,
    IBookRepository dataRepository,
    IBookReferenceRepository referenceRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<BookController> logger)
    : DataCrudControllerBase<BookDto, BookModel>(mapper, dataRepository)
{
    /// <summary>
    /// Hydrates each item's cover from its linked reference, one batched lookup per page (see <see cref="ReferenceImageHydrator"/>).
    /// A book's own <see cref="BookDto.CustomImageUrl"/> then overrides it, through <see cref="ReferenceImageHydrator.HydrateWithCustomOverrideAsync"/>.
    /// Only books, albums and video games have a custom cover, so movies and TV shows use <see cref="ReferenceImageHydrator.HydrateAsync"/>.
    /// </summary>
    protected override Task OnListMappedAsync(List<BookDto> dtos, CancellationToken cancellationToken) =>
        ReferenceImageHydrator.HydrateWithCustomOverrideAsync(dtos, referenceRepository.FindByIdsAsync, x => x.ImageUrl, x => x.CustomImageUrl);

    /// <summary>
    /// Starts a best-effort background match through the default book provider (see <see cref="TvShowController.OnCreatedAsync"/>).
    /// </summary>
    protected override Task OnCreatedAsync(BookModel model)
    {
        var title = model.Title;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveBookAsync(model);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for book '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// "Check for reference match" (see <see cref="TvShowController.RefreshReference"/>).
    /// </summary>
    [HttpPost("{id}/refresh-reference")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<BookDto>> RefreshReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.LinkBookReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }

    /// <summary>
    /// Admin only: clears this book's link and deletes the shared reference document (see <see cref="TvShowController.UnlinkReference"/>).
    /// </summary>
    [HttpPost("{id}/unlink-reference")]
    [Authorize(Policy = "AdminOnly")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<BookDto>> UnlinkReference(string id, CancellationToken cancellationToken)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId(), cancellationToken);
        if (model is null) return NotFound();

        model = await enrichmentService.UnlinkBookReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
