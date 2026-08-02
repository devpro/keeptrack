using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The Explore feature: acclaimed provider titles the caller doesn't already track, with a one-click add and
/// a dismiss/undo. Read-only aggregation plus a create, so a plain <see cref="ControllerBase"/>; the
/// listing/dismissal logic lives in <see cref="ExploreService"/>. Adding resolves the reference from the
/// exact provider id the suggestion came from (not a title search), so the new item is reliably linked.
/// Plain <c>[Authorize]</c> rather than the "MemberOnly" policy because movies and TV shows are the free
/// preview tier; the member-only domains are gated per request instead (see <see cref="RequireAccessTo"/>).
/// </summary>
[ApiController]
[Authorize]
[Route("api/explore")]
public class ExploreController(
    ExploreService exploreService,
    ReferenceEnrichmentService enrichmentService,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository) : ControllerBase
{
    /// <summary>Default number of suggestions returned when the caller doesn't ask for a specific count.</summary>
    private const int DefaultCount = 24;

    /// <summary>
    /// Upper bound on one page's size. Not a cap on how far a caller can explore - the cursor pages through
    /// the whole stored ranking - just on how much a single request returns.
    /// </summary>
    private const int MaxCount = 60;

    /// <summary>Movies and TV shows are part of the free preview tier, so adds count against the quota.</summary>
    private const int FreeTierLimitFactor = 1;

    /// <summary>Video games are a member-only collection, where the free-tier creation quota never applies.</summary>
    private const int MemberOnlyLimitFactor = 0;

    /// <summary>
    /// A page of provider suggestions for a domain (movies, TV shows or video games), ordered by the domain's
    /// primary rating source. Omit <paramref name="after"/> for the first page, then pass back the previous
    /// response's <c>nextCursor</c> to keep going; a null cursor means the ranking is exhausted.
    /// </summary>
    [HttpGet("{type}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<ActionResult<ExploreSuggestionPageDto>> Get(
        ReferenceItemType type, [FromQuery] int? count, [FromQuery] int? after, CancellationToken cancellationToken)
    {
        if (RequireAccessTo(type) is { } denied) return denied;

        var limit = Math.Clamp(count ?? DefaultCount, 1, MaxCount);
        var page = await exploreService.GetSuggestionsAsync(ToDomainType(type), this.GetUserId(), limit, after, cancellationToken);
        return Ok(page);
    }

    /// <summary>
    /// Adds a suggestion to the caller's collection: creates the item and links it to the reference resolved
    /// from the exact provider id (<paramref name="externalId"/>). 403 if a free-preview account is over its
    /// quota, or if the domain is member-only.
    /// </summary>
    [HttpPost("{type}/add/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Add(ReferenceItemType type, string externalId, [FromBody] ExploreAddRequestDto request)
    {
        ToDomainType(type); // validates the domain (Book/Album -> 400)
        if (RequireAccessTo(type) is { } denied) return denied;
        if (string.IsNullOrWhiteSpace(request.Title)) return BadRequest();

        var ownerId = this.GetUserId();
        var quotaError = await FreeTierQuota.CheckAsync(this, LimitFactor(type), () => CountAsync(type, ownerId));
        if (quotaError is not null)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = quotaError });
        }

        // create the item unlinked, then resolve the reference by its exact provider id (upserts the shared
        // reference document and links this just-created item by (title, year) - see ResolveMovieAsync). Using
        // the id, not a title search, is why this links reliably where the ordinary create's search-based
        // auto-resolve can miss a title with several provider candidates.
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
            case ReferenceItemType.VideoGame:
                await videoGameRepository.CreateAsync(new VideoGameModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveVideoGameAsync(request.Title, request.Year, externalId);
                break;
        }

        return NoContent();
    }

    /// <summary>Hides a provider title from the caller's Explore list permanently (until undone). Idempotent.</summary>
    [HttpPost("{type}/dismiss/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Dismiss(ReferenceItemType type, string externalId)
    {
        if (RequireAccessTo(type) is { } denied) return denied;

        await exploreService.DismissAsync(ToDomainType(type), this.GetUserId(), externalId);
        return NoContent();
    }

    /// <summary>Undoes a dismissal so the title can be suggested again.</summary>
    [HttpDelete("{type}/dismiss/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Undismiss(ReferenceItemType type, string externalId)
    {
        if (RequireAccessTo(type) is { } denied) return denied;

        await exploreService.UndismissAsync(ToDomainType(type), this.GetUserId(), externalId);
        return NoContent();
    }

    /// <summary>
    /// Per-domain membership gate, standing in for the controller-wide "MemberOnly" policy that movies and TV
    /// shows must stay outside of. A free-preview account can't hold video games at all, so it gets neither
    /// the suggestions (which would cost provider calls for titles it could never add) nor the dismissals.
    /// Returns null when the caller may proceed, mirroring <see cref="FreeTierQuota.CheckAsync"/>'s shape.
    /// </summary>
    private ObjectResult? RequireAccessTo(ReferenceItemType type) =>
        LimitFactor(type) == MemberOnlyLimitFactor && !this.IsMember()
            ? StatusCode(StatusCodes.Status403Forbidden, new { error = $"{type} tracking is a membership feature." })
            : null;

    private static int LimitFactor(ReferenceItemType type) =>
        type == ReferenceItemType.VideoGame ? MemberOnlyLimitFactor : FreeTierLimitFactor;

    private Task<long> CountAsync(ReferenceItemType type, string ownerId) => type switch
    {
        ReferenceItemType.Movie => movieRepository.CountAsync(ownerId),
        ReferenceItemType.TvShow => tvShowRepository.CountAsync(ownerId),
        ReferenceItemType.VideoGame => videoGameRepository.CountAsync(ownerId),
        _ => throw new ArgumentException($"Explore is not available for {type}.", nameof(type))
    };

    // Only the reference-ranked domains where discovery is meaningful are exposed; Book/Album are rejected
    // (ArgumentException -> 400 via ApiExceptionFilterAttribute) - an aggregate rank doesn't drive discovery
    // there, and neither provider offers a best-of listing to read.
    private static ExploreItemType ToDomainType(ReferenceItemType type) => type switch
    {
        ReferenceItemType.Movie => ExploreItemType.Movie,
        ReferenceItemType.TvShow => ExploreItemType.TvShow,
        ReferenceItemType.VideoGame => ExploreItemType.VideoGame,
        _ => throw new ArgumentException($"Explore is not available for {type}.", nameof(type))
    };
}
