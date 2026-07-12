using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
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
    IDtoMapper<MovieDto, MovieModel> movieMapper,
    IDtoMapper<TvShowDto, TvShowModel> tvShowMapper,
    IDtoMapper<BookDto, BookModel> bookMapper,
    IDtoMapper<VideoGameDto, VideoGameModel> videoGameMapper) : ControllerBase
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
            new VideoGameModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });

        return Ok(new WishlistDto
        {
            Movies = wishlistService.SortMovies(movies.Items).Select(movieMapper.ToDto).ToList(),
            TvShows = wishlistService.SortTvShows(tvShows.Items).Select(tvShowMapper.ToDto).ToList(),
            Books = wishlistService.SortBooks(books.Items).Select(bookMapper.ToDto).ToList(),
            VideoGames = wishlistService.SortVideoGames(videoGames.Items).Select(videoGameMapper.ToDto).ToList()
        });
    }
}
