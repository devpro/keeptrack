using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One video game search hit - title, year and cover art, enough for automatic matching or for an admin
/// to pick from when a match is ambiguous.
/// </summary>
public record VideoGameSearchResult(string ExternalId, string Title, int? Year, string? ImageUrl);

/// <summary>
/// Full details for one game. <paramref name="Ratings"/> is built by the client itself, keyed by its own
/// <see cref="IVideoGameReferenceClient.SupportedRatingSources"/> and already carrying each source's scale -
/// unlike <see cref="BookDetails"/>, whose single 0-5 score the enrichment service can key on its own. Games
/// have two scores per provider on scales that differ per provider (RAWG's 0-5 user score beside Metacritic's
/// 0-100, IGDB's two 0-100 scores), and that knowledge belongs to the provider rather than to a switch in the
/// shared enrichment service.
/// </summary>
public record VideoGameDetails(
    string ExternalId,
    string Title,
    int? Year,
    string? Synopsis,
    List<string> Genres,
    List<string> Platforms,
    string? ImageUrl,
    Dictionary<string, ReferenceRatingModel>? Ratings = null);

/// <summary>
/// One entry from a provider's "top rated" page - the fields a discovery card needs plus every aggregate score
/// the provider reports for it, whichever one the list was ordered by, so switching the admin's displayed
/// source costs no provider call at all. A listing response carries no description, so there is no synopsis
/// here (unlike TMDB's, which does).
/// <para>
/// <c>WebUrl</c> is the game's own page on the provider's website, for a suggestion card to link out to. It
/// comes from the provider rather than being built from <c>ExternalId</c> because both video game sites key
/// their pages on a slug, not on the numeric id - see <see cref="ProviderWebLinks"/>.
/// </para>
/// </summary>
public record VideoGameTopRatedItem(string ExternalId, string Title, int? Year, string? ImageUrl, Dictionary<string, double> Ratings, string? WebUrl);

/// <summary>
/// Provider-agnostic video game lookup, backing <see cref="ReferenceEnrichmentService"/>'s video game
/// resolution/refresh, <see cref="ReferenceDataAdminController"/>'s admin search and the Explore catalogue
/// refresh. Which concrete implementation is active is a deployment-time choice
/// (<c>ReferenceData:VideoGameProvider</c>, see <c>Program.cs</c>) - nothing outside the implementation itself
/// should assume which provider is behind this interface. Same shape as
/// <see cref="IBookReferenceClient"/>, and for the same reason: a second provider was needed once the first
/// became unavailable, and a domain with more than one provider must not hardcode either of them. Interface
/// exists so tests use a fake - never call a real provider's API from a test.
/// </summary>
public interface IVideoGameReferenceClient : IReferenceProviderClient
{
    /// <summary>
    /// The rating source keys this provider owns: the ones it reports values for, and equally the orderings it
    /// can rank its catalogue by (for games those two sets happen to coincide, unlike movies/TV where IMDb has
    /// no catalogue to sort). Read for three things: keying the <c>Ratings</c> map, deciding which stored
    /// ratings a refresh through this provider may overwrite (see
    /// <c>ReferenceEnrichmentService.MergeProviderRatings</c> - a provider must never clear another's values),
    /// and declaring this domain's Explore rankings (<see cref="ExploreRankings.Rankings"/>).
    /// The first is the provider's own default ordering.
    /// </summary>
    IReadOnlyList<string> SupportedRatingSources { get; }

    Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default);

    /// <summary>
    /// Every game this provider holds under exactly <paramref name="title"/> (case-insensitively), rather than
    /// whatever its relevance ranking thinks the phrase means. Empty when it holds none.
    /// <para>
    /// Separate from <see cref="SearchGamesAsync"/> because the two answer different questions, and the
    /// difference is load-bearing for <c>TryAdoptDefaultVideoGameProviderAsync</c>: relevance search is
    /// documented as noisy here (IGDB returns three "Half-Life 2" MMod variants above the canonical game), and
    /// with a small result window the canonical entry can fall outside it entirely - a live probe for
    /// "Resident Evil" came back with five bundles and archive re-releases and no sign of either the 1996
    /// original or the 2002 remake. Adoption asks "does this provider have a game named exactly this", which
    /// an exact-name query answers directly and cheaply, and it is that query's *complete* result that makes
    /// "exactly one candidate" a safe confirmation rather than an artefact of where the window stopped.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default);

    Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of the provider's best games, highest first, ordered by <paramref name="ratingSource"/> - one
    /// of this client's own <see cref="SupportedRatingSources"/>, so no per-title enrichment call is ever
    /// needed to rank the list (unlike movies/TV, whose IMDb ranking has no provider-side ordering to lean on).
    /// An unrecognized source falls back to the provider's default ordering. Returns an empty list past the
    /// last page.
    /// </summary>
    Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default);
}
