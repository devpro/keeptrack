using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/books")]
public class BookController(
    IDtoMapper<BookDto, BookModel> mapper,
    IBookRepository dataRepository,
    ReferenceEnrichmentService enrichmentService,
    IServiceScopeFactory scopeFactory,
    ILogger<BookController> logger)
    : DataCrudControllerBase<BookDto, BookModel>(mapper, dataRepository)
{
    /// <summary>
    /// Fires a best-effort background Open Library match for the new book - see <see cref="TvShowController.OnCreatedAsync"/>.
    /// </summary>
    protected override Task OnCreatedAsync(BookModel model)
    {
        var title = model.Title;
        var year = model.Year;
        var author = model.Author;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var scopedEnrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await scopedEnrichmentService.TryAutoResolveBookAsync(title, year, author);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for book '{Title}'.", title);
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
    public async Task<ActionResult<BookDto>> RefreshReference(string id)
    {
        var model = await dataRepository.FindOneAsync(id, this.GetUserId());
        if (model is null) return NotFound();

        model = await enrichmentService.TryLinkExistingBookReferenceAsync(model);
        return Ok(Mapper.ToDto(model));
    }
}
