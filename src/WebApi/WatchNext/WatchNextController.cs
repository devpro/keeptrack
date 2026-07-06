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

        return Ok(new WatchNextDto
        {
            InProgressShows = watchNextService.ComputeInProgressShows(shows.Items, episodes.Items),
            MoviesToWatch = mapper.Map<List<MovieDto>>(moviesToWatch.Items)
        });
    }
}
