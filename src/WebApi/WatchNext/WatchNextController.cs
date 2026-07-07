using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.WatchNext;

[ApiController]
[Authorize]
[Route("api/watch-next")]
public class WatchNextController(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    IMovieRepository movieRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    WatchNextService watchNextService,
    IMapper mapper) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<WatchNextDto>> Get()
    {
        var ownerId = this.GetUserId();

        var shows = await tvShowRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new TvShowModel { OwnerId = ownerId, Title = string.Empty });
        var episodes = await episodeRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new EpisodeModel { OwnerId = ownerId, TvShowId = string.Empty, SeasonNumber = 0, EpisodeNumber = 0 });
        var moviesToWatch = await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new MovieModel { OwnerId = ownerId, Title = string.Empty, WantToWatch = true });

        // only current shows with a reference link can possibly appear in the result (see WatchNextService),
        // so only those need their (small, bounded) episode guide fetched
        var referencesByShowId = new Dictionary<string, TvShowReferenceModel>();
        foreach (var show in shows.Items.Where(s => s.Status == Domain.Models.TvShowStatus.Current && !string.IsNullOrEmpty(s.ReferenceId)))
        {
            var reference = await tvShowReferenceRepository.FindByIdAsync(show.ReferenceId!);
            if (reference is not null) referencesByShowId[show.Id!] = reference;
        }

        return Ok(new WatchNextDto
        {
            InProgressShows = watchNextService.ComputeInProgressShows(shows.Items, episodes.Items, referencesByShowId),
            MoviesToWatch = mapper.Map<List<MovieDto>>(watchNextService.FilterMoviesToWatch(moviesToWatch.Items))
        });
    }
}
