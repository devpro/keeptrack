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
    /// Every share link the caller has issued, oldest first - the "who did I share this with" list.
    /// </summary>
    [HttpGet("shares")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<WishlistShareDto>>> GetShares()
    {
        var shares = await wishlistShareRepository.FindAllByOwnerIdAsync(this.GetUserId());
        return Ok(shares.ConvertAll(ToDto));
    }

    /// <summary>
    /// Issues a new share link, with an optional label for the caller's own bookkeeping ("Mum",
    /// "Gift exchange"). Each link is independent: one can be revoked without touching the others.
    /// </summary>
    [HttpPost("shares")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<WishlistShareDto>> CreateShare([FromBody] CreateWishlistShareRequestDto? request)
    {
        var share = await wishlistShareRepository.CreateAsync(new WishlistShareModel
        {
            OwnerId = this.GetUserId(),
            Label = string.IsNullOrWhiteSpace(request?.Label) ? null : request.Label.Trim(),
            // 128 bits of randomness: unguessable, which is the entire access control here
            Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()
        });

        return Ok(ToDto(share));
    }

    /// <summary>
    /// Revokes one share link - every copy of that link stops working immediately, the caller's other
    /// links keep working. Owner-scoped: nobody can revoke someone else's share by guessing an id.
    /// </summary>
    [HttpDelete("shares/{id}")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> DeleteShare(string id)
    {
        await wishlistShareRepository.DeleteAsync(id, this.GetUserId());
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

    private static WishlistShareDto ToDto(WishlistShareModel share) =>
        new() { Id = share.Id!, Token = share.Token, Label = share.Label, CreatedAt = share.CreatedAt };

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
