using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One video game search hit: title, year and cover, enough for automatic matching or for an admin to pick from.
/// </summary>
public record VideoGameSearchResult(string ExternalId, string Title, int? Year, string? ImageUrl) : IReferenceSearchCandidate;

/// <summary>
/// Full details for one game.
/// The client builds <paramref name="Ratings"/>, keyed by its <see cref="IVideoGameReferenceClient.SupportedRatingSources"/> with each source's scale, unlike <see cref="BookDetails"/>'s single score.
/// A game provider reports two scores on scales of its own (RAWG's 0 to 5 beside Metacritic's 0 to 100, IGDB's two 0 to 100), which the provider knows rather than the shared enrichment.
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
/// One entry of a provider's "top rated" page: what a discovery card needs, plus every score the provider reports, so switching the displayed source costs no call.
/// A listing carries no description, so there is no synopsis, unlike TMDB's.
/// <para>
/// <c>WebUrl</c> is the game's page on the provider's website, which comes from the provider since game sites key pages on a slug (see <see cref="ProviderWebLinks"/>).
/// </para>
/// </summary>
public record VideoGameTopRatedItem(string ExternalId, string Title, int? Year, string? ImageUrl, Dictionary<string, double> Ratings, string? WebUrl);

/// <summary>
/// Video game lookup independent of the provider, for resolution and refresh, the admin search and the Explore refresh.
/// The default is a deployment choice (<c>ReferenceData:VideoGameProvider</c>), so nothing outside an implementation assumes the provider, as with <see cref="IBookReferenceClient"/>.
/// An interface, so tests use a fake.
/// </summary>
public interface IVideoGameReferenceClient : IReferenceProviderClient
{
    /// <summary>
    /// The rating source keys this provider owns: those it reports and, for games, the orderings it ranks its catalogue by.
    /// They key the <c>Ratings</c> map, decide which stored ratings a refresh may overwrite (<c>ReferenceEnrichmentService.MergeProviderRatings</c>, so a provider never clears another's), and declare the Explore rankings (<see cref="ExploreRankings.Rankings"/>).
    /// The first is the provider's default ordering.
    /// </summary>
    IReadOnlyList<string> SupportedRatingSources { get; }

    Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default);

    /// <summary>
    /// Every game this provider holds under exactly <paramref name="title"/>, case-insensitively, rather than what its relevance ranking makes of the phrase.
    /// Empty when there is none.
    /// <para>
    /// Apart from <see cref="SearchGamesAsync"/>, since relevance is noisy: IGDB puts three "Half-Life 2" mods above the game, and "Resident Evil" returns bundles before either the original or the remake.
    /// Adoption asks whether a game is named exactly this, and the query's complete result makes "exactly one candidate" a safe confirmation rather than where a window stopped.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default);

    /// <summary>
    /// Every game whose title contains all of <paramref name="words"/> as substrings, in any order: the last resort for a title neither the exact lookup nor relevance reaches.
    /// <para>
    /// It serves a reference spelled without the provider's punctuation.
    /// "Marvel Avengers" is IGDB's "Marvel's Avengers", which the exact lookup misses and relevance answers with LEGO packs, while <c>name ~ *"marvel"* &amp; name ~ *"avengers"*</c> finds it.
    /// </para>
    /// <para>
    /// Unranked, so the caller shortlists the result rather than showing it whole (see <c>ReferenceEnrichmentService.FindAdoptionCandidatesAsync</c>).
    /// </para>
    /// </summary>
    Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default);

    /// <summary>
    /// The game this provider publishes under <paramref name="identifier"/>: its numeric id, or the slug of its page URL (see <see cref="ProviderWebLinks.TryReadIdentifier"/>).
    /// Null when there is none, never an exception, since a wrong pasted address is an ordinary "no result".
    /// <para>
    /// The reconciliation screen's escape hatch: no spelling makes IGDB's relevance search return "Marvel's Avengers", while its page, which a human can open and copy, names it exactly.
    /// </para>
    /// </summary>
    Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default);

    Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of the provider's best games, ordered by <paramref name="ratingSource"/>, one of its <see cref="SupportedRatingSources"/>, so ranking needs no call per title.
    /// An unknown source falls back to the default ordering, and a page past the last is empty.
    /// </summary>
    Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default);
}
