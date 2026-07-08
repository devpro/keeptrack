using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/wishlist")]
public class WishlistController(
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IBookRepository bookRepository,
    IVideoGameRepository videoGameRepository,
    WishlistService wishlistService,
    IMapper mapper) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<WishlistDto>> Get()
    {
        var ownerId = this.GetUserId();

        var movies = await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new MovieModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });
        var tvShows = await tvShowRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new TvShowModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });
        var books = await bookRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty, IsWishlisted = true });
        var videoGames = await videoGameRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new VideoGameModel { OwnerId = ownerId, Title = string.Empty, Platform = string.Empty, State = string.Empty, IsWishlisted = true });

        return Ok(new WishlistDto
        {
            Movies = mapper.Map<List<MovieDto>>(wishlistService.SortMovies(movies.Items)),
            TvShows = mapper.Map<List<TvShowDto>>(wishlistService.SortTvShows(tvShows.Items)),
            Books = mapper.Map<List<BookDto>>(wishlistService.SortBooks(books.Items)),
            VideoGames = mapper.Map<List<VideoGameDto>>(wishlistService.SortVideoGames(videoGames.Items))
        });
    }
}
