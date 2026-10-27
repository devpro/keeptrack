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
        var moviesToWatch = await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new MovieModel { OwnerId = ownerId, Title = string.Empty, WantToWatch = true });

        // only current, linked shows can appear (see WatchNextService), so only those fetch their episodes and episode guide
        var candidateShows = shows.Items
            .Where(s => s.State == Domain.Models.TvShowStatus.Current && !string.IsNullOrEmpty(s.ReferenceId))
            .ToList();

        var episodes = await episodeRepository.FindByShowIdsAsync(ownerId, candidateShows.Select(s => s.Id!).ToList());

        // one batched lookup rather than a round trip per show
        var referencesById = (await tvShowReferenceRepository.FindByIdsAsync(
                candidateShows.Select(s => s.ReferenceId!).Distinct().ToList()))
            .ToDictionary(r => r.Id!);
        var referencesByShowId = candidateShows
            .Where(s => referencesById.ContainsKey(s.ReferenceId!))
            .ToDictionary(s => s.Id!, s => referencesById[s.ReferenceId!]);

        var result = new WatchNextDto
        {
            InProgressShows = WatchNextService.ComputeInProgressShows(shows.Items, episodes, referencesByShowId)
                .Select(inProgressShowMapper.ToDto).ToList(),
            MoviesToWatch = WatchNextService.FilterMoviesToWatch(moviesToWatch.Items).Select(movieMapper.ToDto).ToList()
        };

        // shows take their covers from the references already fetched, unlike the movies hydrated below
        foreach (var dto in result.InProgressShows)
        {
            if (referencesByShowId.TryGetValue(dto.TvShowId, out var reference)) dto.ImageUrl = reference.ImageUrl;
        }
        await ReferenceImageHydrator.HydrateAsync(result.MoviesToWatch, movieReferenceRepository.FindByIdsAsync, x => x.ImageUrl);

        return Ok(result);
    }
}
