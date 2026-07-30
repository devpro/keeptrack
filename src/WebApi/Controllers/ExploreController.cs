using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The Explore feature: acclaimed provider titles (TMDB top-rated) the caller doesn't already track, with a
/// one-click add and a dismiss/undo. Read-only aggregation plus a create, so a plain <see cref="ControllerBase"/>;
/// the listing/dismissal logic lives in <see cref="ExploreService"/>. Adding resolves the reference from the
/// exact TMDB id the suggestion came from (not a title search), so the new item is reliably linked. Available
/// to every authenticated account because movies and TV shows are the free preview tier.
/// </summary>
[ApiController]
[Authorize]
[Route("api/explore")]
public class ExploreController(
    ExploreService exploreService,
    ReferenceEnrichmentService enrichmentService,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository) : ControllerBase
{
    /// <summary>Default number of suggestions returned when the caller doesn't ask for a specific count.</summary>
    private const int DefaultCount = 24;

    /// <summary>Upper bound on the count, so one request can't pull an unbounded number of provider pages.</summary>
    private const int MaxCount = 60;

    /// <summary>Movies and TV shows are both part of the free preview tier, so adds count against the quota.</summary>
    private const int FreeTierLimitFactor = 1;

    /// <summary>The top provider suggestions for a domain (movies or TV shows today).</summary>
    [HttpGet("{type}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<List<ExploreSuggestionDto>>> Get(ReferenceItemType type, [FromQuery] int? count, CancellationToken cancellationToken)
    {
        var limit = Math.Clamp(count ?? DefaultCount, 1, MaxCount);
        var suggestions = await exploreService.GetSuggestionsAsync(ToDomainType(type), this.GetUserId(), limit, cancellationToken);
        return Ok(suggestions);
    }

    /// <summary>
    /// Adds a suggestion to the caller's collection: creates the item and links it to the reference resolved
    /// from the exact TMDB id (<paramref name="externalId"/>). 403 if a free-preview account is over its quota.
    /// </summary>
    [HttpPost("{type}/add/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Add(ReferenceItemType type, string externalId, [FromBody] ExploreAddRequestDto request)
    {
        ToDomainType(type); // validates the domain (Book/Album -> 400)
        if (string.IsNullOrWhiteSpace(request.Title)) return BadRequest();

        var ownerId = this.GetUserId();
        var quotaError = await FreeTierQuota.CheckAsync(this, FreeTierLimitFactor, () => CountAsync(type, ownerId));
        if (quotaError is not null)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = quotaError });
        }

        // create the item unlinked, then resolve the reference by its exact TMDB id (upserts the shared
        // reference document and links this just-created item by (title, year) - see ResolveMovieAsync). Using
        // the id, not a title search, is why this links reliably where the ordinary create's search-based
        // auto-resolve can miss a title with several TMDB candidates.
        switch (type)
        {
            case ReferenceItemType.Movie:
                await movieRepository.CreateAsync(new MovieModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveMovieAsync(request.Title, request.Year, externalId);
                break;
            case ReferenceItemType.TvShow:
                await tvShowRepository.CreateAsync(new TvShowModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, externalId);
                break;
        }

        return NoContent();
    }

    /// <summary>Hides a provider title from the caller's Explore list permanently (until undone). Idempotent.</summary>
    [HttpPost("{type}/dismiss/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> Dismiss(ReferenceItemType type, string externalId)
    {
        await exploreService.DismissAsync(ToDomainType(type), this.GetUserId(), externalId);
        return NoContent();
    }

    /// <summary>Undoes a dismissal so the title can be suggested again.</summary>
    [HttpDelete("{type}/dismiss/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> Undismiss(ReferenceItemType type, string externalId)
    {
        await exploreService.UndismissAsync(ToDomainType(type), this.GetUserId(), externalId);
        return NoContent();
    }

    private Task<long> CountAsync(ReferenceItemType type, string ownerId) => type switch
    {
        ReferenceItemType.Movie => movieRepository.CountAsync(ownerId),
        ReferenceItemType.TvShow => tvShowRepository.CountAsync(ownerId),
        _ => throw new ArgumentException($"Explore is not available for {type}.", nameof(type))
    };

    // Only the reference-ranked domains where discovery is meaningful are exposed; Book/Album are rejected
    // (ArgumentException -> 400 via ApiExceptionFilterAttribute). Video games join here in a later increment.
    private static ExploreItemType ToDomainType(ReferenceItemType type) => type switch
    {
        ReferenceItemType.Movie => ExploreItemType.Movie,
        ReferenceItemType.TvShow => ExploreItemType.TvShow,
        _ => throw new ArgumentException($"Explore is not available for {type}.", nameof(type))
    };
}
