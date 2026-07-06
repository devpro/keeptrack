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
[Route("api/tv-shows")]
public class TvShowController(IMapper mapper, ITvShowRepository dataRepository, IServiceScopeFactory scopeFactory, ILogger<TvShowController> logger)
    : DataCrudControllerBase<TvShowDto, TvShowModel>(mapper, dataRepository)
{
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
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveTvShowAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for TV show '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }
}
