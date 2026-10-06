using Keeptrack.Common.System;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The search policy of every <see cref="IVideoGameReferenceClient"/>, written once like <see cref="BookReferenceClientBase"/>:
/// each provider supplies its query shapes, and the order and handling of answers live here.
/// <para>
/// A relevance search alone is no answer in this domain.
/// IGDB's <c>search "Code Vein"</c> ranks the 2019 game sixth, behind its sequel and DLC, so a list of five never holds it.
/// For "Resident Evil", bundles and re-releases fill the first six ranks.
/// </para>
/// <para>
/// Two rules follow.
/// A game named exactly so is fetched directly (<see cref="IVideoGameReferenceClient.FindGamesByExactTitleAsync"/>),
/// so a perfect match is always a candidate, however deep relevance buries it.
/// The relevance query reads a <see cref="RelevancePoolSize"/> pool,
/// and <see cref="ReferenceMatchRules.OrderByBestMatch"/> picks what is shown, since truncating before ranking loses the right candidate.
/// </para>
/// </summary>
public abstract class VideoGameReferenceClientBase : IVideoGameReferenceClient
{
    /// <inheritdoc />
    public abstract string ProviderKey { get; }

    /// <inheritdoc />
    public abstract string DisplayName { get; }

    /// <inheritdoc />
    public abstract IReadOnlyList<string> SupportedRatingSources { get; }

    /// <inheritdoc />
    public async Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(title)) return [];

        var candidates = new List<VideoGameSearchResult>();
        Accumulate(candidates, await FindGamesByExactTitleAsync(title, cancellationToken));
        Accumulate(candidates, await SearchByRelevanceAsync(title, RelevancePoolSize, cancellationToken));

        // the ordering every candidate list uses, a perfect match first, never the provider's relevance, which buries answers
        return ReferenceMatchRules.OrderByBestMatch(candidates, title, year).Take(MaxResults).ToList();
    }

    /// <summary>
    /// One page of the provider's relevance search for <paramref name="title"/>, up to <paramref name="limit"/> results, in its own order.
    /// <para>
    /// It takes no year, like <see cref="BookReferenceClientBase.SearchByTitleAsync"/>: a provider's date is the earliest worldwide release,
    /// while a tenant types the year of their own release, so a filter would drop a good match.
    /// <see cref="ReferenceMatchRules.YearRank"/> uses the year instead, where a wrong one costs a place rather than the result.
    /// </para>
    /// </summary>
    protected abstract Task<IReadOnlyList<VideoGameSearchResult>> SearchByRelevanceAsync(string title, int limit, CancellationToken cancellationToken);

    /// <inheritdoc />
    public abstract Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public abstract Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default);

    private static void Accumulate(List<VideoGameSearchResult> candidates, IReadOnlyList<VideoGameSearchResult> found) =>
        candidates.AddRange(found.Where(result => candidates.TrueForAll(known => known.ExternalId != result.ExternalId)));

    /// <summary>
    /// How many candidates a search reports, a picker's worth: the best of the <see cref="RelevancePoolSize"/> asked for.
    /// </summary>
    private const int MaxResults = 5;

    /// <summary>
    /// How deep into the relevance ranking a search reads before choosing.
    /// IGDB's games named exactly "Resident Evil" sit at ranks 7 to 13 of a 48-entry ranking, and "Code Vein" at 6, so five is too shallow.
    /// One page either way, so the depth costs nothing.
    /// </summary>
    private const int RelevancePoolSize = 50;
}
