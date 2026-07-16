using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Per-owner collection counts - a read-only cross-entity aggregation like WatchNext/Wishlist, so a plain
/// <see cref="ControllerBase"/> rather than <see cref="DataCrudControllerBase{TDto,TModel}"/>. There is no
/// Domain service here on purpose: nine independent counts involve no computation to extract.
/// </summary>
[ApiController]
[Authorize]
[Route("api/stats")]
public class StatsController(
    IBookRepository bookRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    IAlbumRepository albumRepository,
    IPlaylistRepository playlistRepository,
    IVideoGameRepository videoGameRepository,
    ICarRepository carRepository,
    IHouseRepository houseRepository) : ControllerBase
{
    /// <summary>
    /// How many items the caller has in each collection.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<CollectionStatsDto>> Get()
    {
        var ownerId = this.GetUserId();

        return Ok(new CollectionStatsDto
        {
            Books = await bookRepository.CountAsync(ownerId),
            Movies = await movieRepository.CountAsync(ownerId),
            TvShows = await tvShowRepository.CountAsync(ownerId),
            EpisodesWatched = await episodeRepository.CountAsync(ownerId),
            Albums = await albumRepository.CountAsync(ownerId),
            Playlists = await playlistRepository.CountAsync(ownerId),
            VideoGames = await videoGameRepository.CountAsync(ownerId),
            Cars = await carRepository.CountAsync(ownerId),
            Houses = await houseRepository.CountAsync(ownerId)
        });
    }
}
