using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Explore: acclaimed titles the caller does not track, with a one-click add and a dismiss with undo.
/// A plain <see cref="ControllerBase"/>, the listing and dismissal logic living in <see cref="ExploreService"/>.
/// Adding resolves the reference from the suggestion's exact provider id rather than a title search, so the new item is reliably linked.
/// Plain <c>[Authorize]</c> rather than "MemberOnly", since movies and TV shows are in the free tier, with member-only domains gated per request (<see cref="RequireAccessTo"/>).
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
    /// <summary>Number of suggestions returned when the caller asks for no count.</summary>
    private const int DefaultCount = 24;

    /// <summary>
    /// Upper bound of one page, not of how far a caller explores, since the cursor pages through the whole ranking.
    /// </summary>
    private const int MaxCount = 60;

    /// <summary>Movies and TV shows are in the free preview tier, so adds count against the quota.</summary>
    private const int FreeTierLimitFactor = 1;

    /// <summary>Video games are member only, where the free-tier quota never applies.</summary>
    private const int MemberOnlyLimitFactor = 0;

    /// <summary>
    /// A page of provider suggestions for a domain (movies, TV shows or video games), ordered by the domain's primary rating source.
    /// <paramref name="after"/> is omitted for the first page, then the previous response's <c>nextCursor</c>, and a null cursor means the ranking is exhausted.
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
    /// Adds a suggestion to the caller's collection: creates the item and links it to the reference resolved from <paramref name="externalId"/>.
    /// 403 when a free account is over its quota, or the domain is member only.
    /// </summary>
    [HttpPost("{type}/add/{externalId}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(403)]
    public async Task<IActionResult> Add(ReferenceItemType type, string externalId, [FromBody] ExploreAddRequestDto request)
    {
        ToDomainType(type); // validates the domain, books and albums answering 400
        if (RequireAccessTo(type) is { } denied) return denied;
        if (string.IsNullOrWhiteSpace(request.Title)) return BadRequest();

        var ownerId = this.GetUserId();
        var quotaError = await FreeTierQuota.CheckAsync(this, LimitFactor(type), () => CountAsync(type, ownerId));
        if (quotaError is not null)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = quotaError });
        }

        // Created unlinked, then linked to the reference resolved from the exact provider id.
        // The id links reliably where a title search could miss a title with several candidates.
        switch (type)
        {
            case ReferenceItemType.Movie:
                var movie = await movieRepository.CreateAsync(new MovieModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveMovieAsync(request.Title, request.Year, externalId, ReferenceLinkTarget.Item(movie.Id!, ownerId));
                break;
            case ReferenceItemType.TvShow:
                var show = await tvShowRepository.CreateAsync(new TvShowModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveTvShowAsync(request.Title, request.Year, externalId, ReferenceLinkTarget.Item(show.Id!, ownerId));
                break;
            case ReferenceItemType.VideoGame:
                var game = await videoGameRepository.CreateAsync(new VideoGameModel { OwnerId = ownerId, Title = request.Title, Year = request.Year });
                await enrichmentService.ResolveVideoGameAsync(request.Title, request.Year, externalId, ReferenceLinkTarget.Item(game.Id!, ownerId));
                break;
        }

        return NoContent();
    }

    /// <summary>Hides a title from the caller's Explore list until undone, idempotently.</summary>
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
    /// The membership gate per domain, in place of a controller-wide "MemberOnly" policy that would exclude movies and TV shows.
    /// A free account cannot hold video games, so it gets neither their suggestions nor their dismissals.
    /// Null when the caller may proceed, like <see cref="FreeTierQuota.CheckAsync"/>.
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

    // only domains with a best-of listing are exposed, books and albums throwing ArgumentException, which becomes a 400
    private static ExploreItemType ToDomainType(ReferenceItemType type) => type switch
    {
        ReferenceItemType.Movie => ExploreItemType.Movie,
        ReferenceItemType.TvShow => ExploreItemType.TvShow,
        ReferenceItemType.VideoGame => ExploreItemType.VideoGame,
        _ => throw new ArgumentException($"Explore is not available for {type}.", nameof(type))
    };
}
