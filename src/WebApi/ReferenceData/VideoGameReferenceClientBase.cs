using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The search policy every <see cref="IVideoGameReferenceClient"/> shares, written once instead of copied per
/// provider - the same shape as <see cref="BookReferenceClientBase"/>, and for the same reason: each provider
/// supplies only its own query shapes, while the order they are asked in and what is done with the answers
/// lives here.
/// <para>
/// It exists because a plain relevance search is not an answer on its own in this domain. Confirmed live
/// against IGDB: <c>search "Code Vein"</c> ranks the 2019 game *sixth*, behind its own sequel, three DLC packs
/// and a season pass, so the five results an admin was shown never contained the one title that matched the
/// requested name and year exactly. "Resident Evil" is worse - the first six hits are bundles and archive
/// re-releases, and the seven games actually named "Resident Evil" start at rank seven.
/// </para>
/// <para>
/// Two rules follow, and both are needed. First, a game the provider holds under exactly this name is fetched
/// directly (<see cref="IVideoGameReferenceClient.FindGamesByExactTitleAsync"/>) rather than hoped for from the
/// relevance ranking, which is what guarantees a perfect title match is always among the candidates - relevance
/// can bury it arbitrarily deep, or (confirmed for "Marvel's Avengers") never return it at all. Second, the
/// relevance query asks for a <see cref="RelevancePoolSize"/> pool rather than the handful that is displayed,
/// and <see cref="ReferenceMatchRules.OrderByBestMatch"/> decides which of them are shown - because truncating
/// first and ranking second is exactly how the right candidate got lost.
/// </para>
/// <para>
/// The ordering itself is not this class's own: it is the one the admin reconciliation row and the substring
/// shortlist already used, so every list of candidates a human is shown agrees about which looks best.
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

        // the same ordering the admin reconciliation row and the substring shortlist use - a perfect match
        // first, then whatever is closest to what was asked for. The provider's own relevance order is
        // deliberately not consulted: it is what buried the answer at rank six in the first place.
        return ReferenceMatchRules.OrderByBestMatch(candidates, title, year).Take(MaxResults).ToList();
    }

    /// <summary>
    /// One page of the provider's own relevance search for <paramref name="title"/>, up to
    /// <paramref name="limit"/> results, in whatever order it ranks them.
    /// <para>
    /// Takes no year on purpose, the same call <see cref="BookReferenceClientBase.SearchByTitleAsync"/> makes:
    /// a provider's release date is its earliest worldwide one, while a tenant types the year of the release
    /// they actually own, so filtering on it server-side turns a good match into no match at all - the "an
    /// optional narrowing parameter must never silently zero out results a broader search would find" rule that
    /// <see cref="DiscogsClient"/>'s and <see cref="OpenLibraryClient"/>'s retries exist for. The year is used
    /// in <see cref="ReferenceMatchRules.YearRank"/> instead, where being wrong about it costs a place in the
    /// list rather than the whole result.
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
    /// How many candidates a search reports - a picker's worth, not a catalogue's. It is a *display* bound now
    /// rather than the query bound it used to be: what the provider is asked for is
    /// <see cref="RelevancePoolSize"/>, and these are the best of them.
    /// </summary>
    private const int MaxResults = 5;

    /// <summary>
    /// How deep into the provider's relevance ranking a search reads before choosing what to show. Measured
    /// against the live IGDB catalogue: the games named exactly "Resident Evil" begin at rank 7 and run to rank
    /// 13, behind six bundles and archive editions, and "Code Vein" is at rank 6 - so a pool of five was
    /// reliably too shallow to contain the answer, while the whole "Resident Evil" ranking is only 48 entries
    /// deep. One page either way, so the extra depth costs nothing per search.
    /// </summary>
    private const int RelevancePoolSize = 50;
}
