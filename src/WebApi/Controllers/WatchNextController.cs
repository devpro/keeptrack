using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/watch-next")]
public class WatchNextController(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    IMovieRepository movieRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    InProgressShowDtoMapper inProgressShowMapper,
    IDtoMapper<MovieDto, MovieModel> movieMapper) : ControllerBase
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
        foreach (var show in shows.Items.Where(s => s.State == Domain.Models.TvShowStatus.Current && !string.IsNullOrEmpty(s.ReferenceId)))
        {
            var reference = await tvShowReferenceRepository.FindByIdAsync(show.ReferenceId!);
            if (reference is not null) referencesByShowId[show.Id!] = reference;
        }

        var result = new WatchNextDto
        {
            InProgressShows = WatchNextService.ComputeInProgressShows(shows.Items, episodes.Items, referencesByShowId)
                .Select(inProgressShowMapper.ToDto).ToList(),
            MoviesToWatch = WatchNextService.FilterMoviesToWatch(moviesToWatch.Items).Select(movieMapper.ToDto).ToList()
        };

        // in-progress shows' posters come straight from the reference documents already fetched above -
        // no second lookup needed, unlike the movies' generic hydration below.
        foreach (var dto in result.InProgressShows)
        {
            if (referencesByShowId.TryGetValue(dto.TvShowId, out var reference)) dto.ImageUrl = reference.ImageUrl;
        }
        await ReferenceImageHydrator.HydrateAsync(result.MoviesToWatch, movieReferenceRepository.FindByIdsAsync, x => x.ImageUrl);

        return Ok(result);
    }
}
