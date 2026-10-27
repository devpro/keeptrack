using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Read-only access to the shared reference collections, for any authenticated user.
/// Apart from the item controllers, since this is shared data, not the tenant's own documents.
/// </summary>
[ApiController]
[Authorize]
[Route("api/reference-data")]
public class ReferenceDataController(
    TvShowReferenceDtoMapper tvShowReferenceMapper,
    MovieReferenceDtoMapper movieReferenceMapper,
    BookReferenceDtoMapper bookReferenceMapper,
    VideoGameReferenceDtoMapper videoGameReferenceMapper,
    AlbumReferenceDtoMapper albumReferenceMapper,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    IPersonReferenceRepository personReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository)
    : ControllerBase
{
    [HttpGet("tv-shows/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<TvShowReferenceDto>> GetTvShow(string referenceId)
    {
        var model = await tvShowReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = tvShowReferenceMapper.ToDto(model);
        dto.Cast = await HydrateCastAsync(model.Cast);
        return Ok(dto);
    }

    [HttpGet("movies/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<MovieReferenceDto>> GetMovie(string referenceId)
    {
        var model = await movieReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = movieReferenceMapper.ToDto(model);
        dto.Cast = await HydrateCastAsync(model.Cast);
        return Ok(dto);
    }

    [HttpGet("books/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<BookReferenceDto>> GetBook(string referenceId)
    {
        var model = await bookReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = bookReferenceMapper.ToDto(model);
        (dto.AuthorName, dto.AuthorImageUrl) = await HydratePersonAsync(model.AuthorReferenceId);
        return Ok(dto);
    }

    [HttpGet("video-games/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<VideoGameReferenceDto>> GetVideoGame(string referenceId)
    {
        var model = await videoGameReferenceRepository.FindByIdAsync(referenceId);
        return model is null ? NotFound() : Ok(videoGameReferenceMapper.ToDto(model));
    }

    [HttpGet("albums/{referenceId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<AlbumReferenceDto>> GetAlbum(string referenceId)
    {
        var model = await albumReferenceRepository.FindByIdAsync(referenceId);
        if (model is null) return NotFound();

        var dto = albumReferenceMapper.ToDto(model);
        (dto.ArtistName, dto.ArtistImageUrl) = await HydratePersonAsync(model.ArtistReferenceId);
        return Ok(dto);
    }

    /// <summary>
    /// Joins one person reference id (a book's author, an album's artist) against person_reference, the single counterpart of <see cref="HydrateCastAsync"/>.
    /// </summary>
    private async Task<(string? Name, string? ImageUrl)> HydratePersonAsync(string? personReferenceId)
    {
        if (string.IsNullOrEmpty(personReferenceId)) return (null, null);

        var person = await personReferenceRepository.FindByIdAsync(personReferenceId);
        return person is null ? (null, null) : (person.Name, person.ProfileImageUrl);
    }

    /// <summary>
    /// Joins the embedded cast against person_reference into the DTO the client renders, which a generated mapper cannot do (see <see cref="TvShowReferenceDtoMapper"/>).
    /// </summary>
    private async Task<List<CastMemberDto>> HydrateCastAsync(List<CastMemberModel> cast)
    {
        var result = new List<CastMemberDto>();
        foreach (var member in cast.OrderBy(c => c.Order))
        {
            var person = await personReferenceRepository.FindByIdAsync(member.PersonReferenceId);
            if (person is null) continue;

            result.Add(new CastMemberDto { Name = person.Name, CharacterName = member.CharacterName, ProfileImageUrl = person.ProfileImageUrl });
        }

        return result;
    }
}
