using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Lets an admin/maintainer resolve titles the automatic TMDB match couldn't confidently handle
/// (ambiguous or zero results). Not per-tenant CRUD, so this doesn't extend <see cref="Controllers.DataCrudControllerBase{TDto,TModel}"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "AdminOnly")]
[Route("api/reference-data")]
public class ReferenceDataAdminController(
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository,
    ITmdbClient tmdbClient,
    ReferenceEnrichmentService enrichmentService) : ControllerBase
{
    /// <summary>
    /// Distinct (title, year) pairs, across every tenant, still missing a reference-data link.
    /// </summary>
    [HttpGet("unresolved")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<UnresolvedReferenceDto>>> GetUnresolved([FromQuery] ReferenceItemType type)
    {
        var pairs = type == ReferenceItemType.TvShow
            ? await tvShowRepository.FindDistinctUnresolvedTitleYearsAsync()
            : await movieRepository.FindDistinctUnresolvedTitleYearsAsync();

        return Ok(pairs.Select(p => new UnresolvedReferenceDto { Type = type, Title = p.Title, Year = p.Year }).ToList());
    }

    /// <summary>
    /// How many search candidates get enriched with a poster and top cast names - bounds the extra
    /// per-candidate credits calls to a small, admin-facing action, not the full ~20-result TMDB page.
    /// </summary>
    private const int MaxEnrichedCandidates = 5;

    private const int MaxCastNamesPerCandidate = 3;

    /// <summary>
    /// Live TMDB search, for an admin to pick the right candidate for an unresolved title. The top
    /// candidates are enriched with a poster and top-billed cast names to help tell apart near-identical
    /// results (remakes, regional variants, sequels sharing a title).
    /// </summary>
    [HttpGet("search")]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<ReferenceSearchResultDto>>> Search([FromQuery] ReferenceItemType type, [FromQuery] string title, [FromQuery] int? year)
    {
        var results = type == ReferenceItemType.TvShow
            ? await tmdbClient.SearchTvShowAsync(title, year)
            : await tmdbClient.SearchMovieAsync(title, year);

        var dtos = new List<ReferenceSearchResultDto>();
        foreach (var result in results.Take(MaxEnrichedCandidates))
        {
            var cast = type == ReferenceItemType.TvShow
                ? await tmdbClient.GetTvShowCastAsync(result.TmdbId)
                : await tmdbClient.GetMovieCastAsync(result.TmdbId);

            dtos.Add(new ReferenceSearchResultDto
            {
                TmdbId = result.TmdbId,
                Title = result.Title,
                Year = result.Year,
                Synopsis = result.Synopsis,
                PosterUrl = result.PosterUrl,
                TopCastNames = cast.OrderBy(c => c.Order).Take(MaxCastNamesPerCandidate).Select(c => c.Name).ToList()
            });
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Links every tenant's (Title, Year) match to the chosen TMDB id and fetches its full details.
    /// </summary>
    [HttpPost("link")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Link([FromBody] LinkReferenceRequestDto request)
    {
        if (request.Type == ReferenceItemType.TvShow)
        {
            await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, request.TmdbId);
        }
        else
        {
            await enrichmentService.ResolveMovieAsync(request.Title, request.Year, request.TmdbId);
        }

        return NoContent();
    }
}
