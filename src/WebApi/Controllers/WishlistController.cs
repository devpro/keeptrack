using System.Security.Cryptography;
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
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IWishlistShareRepository wishlistShareRepository,
    IDtoMapper<MovieDto, MovieModel> movieMapper,
    IDtoMapper<TvShowDto, TvShowModel> tvShowMapper,
    IDtoMapper<BookDto, BookModel> bookMapper,
    IDtoMapper<VideoGameDto, VideoGameModel> videoGameMapper) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(200)]
    [ProducesResponseType(500)]
    public async Task<ActionResult<WishlistDto>> Get() => Ok(await BuildWishlistAsync(this.GetUserId()));

    /// <summary>
    /// The caller's active wishlist share link, when one exists.
    /// </summary>
    [HttpGet("share")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<WishlistShareDto>> GetShare()
    {
        var share = await wishlistShareRepository.FindByOwnerIdAsync(this.GetUserId());
        if (share is null) return NotFound();

        return Ok(new WishlistShareDto { Token = share.Token });
    }

    /// <summary>
    /// Creates the caller's wishlist share link, or returns the existing one (idempotent). To rotate a
    /// leaked link, delete the share first - recreating issues a fresh token and old copies stay dead.
    /// </summary>
    [HttpPost("share")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<WishlistShareDto>> CreateShare()
    {
        var ownerId = this.GetUserId();
        var share = await wishlistShareRepository.FindByOwnerIdAsync(ownerId)
                    ?? await wishlistShareRepository.CreateAsync(new WishlistShareModel
                    {
                        OwnerId = ownerId,
                        // 128 bits of randomness: unguessable, which is the entire access control here
                        Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()
                    });

        return Ok(new WishlistShareDto { Token = share.Token });
    }

    /// <summary>
    /// Revokes the caller's wishlist share link - every copy of the link stops working immediately.
    /// </summary>
    [HttpDelete("share")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> DeleteShare()
    {
        await wishlistShareRepository.DeleteByOwnerIdAsync(this.GetUserId());
        return NoContent();
    }

    /// <summary>
    /// The live wishlist behind a share token - the one anonymous read in the app, so a recipient
    /// needs no account. The token's 128-bit randomness is the access control; an unknown or revoked
    /// token is an indistinguishable 404.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("shared/{token}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<WishlistDto>> GetShared(string token)
    {
        var share = await wishlistShareRepository.FindByTokenAsync(token);
        if (share is null) return NotFound();

        return Ok(await BuildWishlistAsync(share.OwnerId));
    }

    private async Task<WishlistDto> BuildWishlistAsync(string ownerId)
    {
        var movies = await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new MovieModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });
        var tvShows = await tvShowRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new TvShowModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });
        var books = await bookRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty, IsWishlisted = true });
        var videoGames = await videoGameRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new VideoGameModel { OwnerId = ownerId, Title = string.Empty, IsWishlisted = true });

        var result = new WishlistDto
        {
            Movies = WishlistService.SortMovies(movies.Items).Select(movieMapper.ToDto).ToList(),
            TvShows = WishlistService.SortTvShows(tvShows.Items).Select(tvShowMapper.ToDto).ToList(),
            Books = WishlistService.SortBooks(books.Items).Select(bookMapper.ToDto).ToList(),
            VideoGames = WishlistService.SortVideoGames(videoGames.Items).Select(videoGameMapper.ToDto).ToList()
        };

        await ReferenceImageHydrator.HydrateAsync(result.Movies, movieReferenceRepository.FindByIdsAsync, x => x.ImageUrl);
        await ReferenceImageHydrator.HydrateAsync(result.TvShows, tvShowReferenceRepository.FindByIdsAsync, x => x.ImageUrl);
        await ReferenceImageHydrator.HydrateAsync(result.Books, bookReferenceRepository.FindByIdsAsync, x => x.ImageUrl);
        await ReferenceImageHydrator.HydrateAsync(result.VideoGames, videoGameReferenceRepository.FindByIdsAsync, x => x.ImageUrl);

        return result;
    }
}
