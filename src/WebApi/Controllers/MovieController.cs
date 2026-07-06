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
[Route("api/movies")]
public class MovieController(IMapper mapper, IMovieRepository dataRepository, IServiceScopeFactory scopeFactory, ILogger<MovieController> logger)
    : DataCrudControllerBase<MovieDto, MovieModel>(mapper, dataRepository)
{
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
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveMovieAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Background reference-data match failed for movie '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }
}
