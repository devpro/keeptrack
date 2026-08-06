using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Stand-in for a video game provider. Parameterized by provider key and rating sources rather than fixed to
/// one, so a test can register two of them and exercise the multi-provider behaviour (which client a refresh
/// picks, whose ratings a merge is allowed to replace) without a second fake class.
/// </summary>
internal sealed class FakeVideoGameReferenceClient : IVideoGameReferenceClient
{
    private readonly List<VideoGameSearchResult> _searchResults;

    public string ProviderKey { get; }

    public string DisplayName { get; }

    public IReadOnlyList<string> SupportedRatingSources { get; }

    public Dictionary<string, VideoGameDetails> Details { get; } = new();

    /// <summary>One page of Explore discovery results, keyed by page number - empty pages end the paging loop.</summary>
    public Dictionary<int, IReadOnlyList<VideoGameTopRatedItem>> TopRatedPages { get; } = new();

    /// <summary>The rating source the last <see cref="GetTopRatedGamesAsync"/> call asked the provider to order by.</summary>
    public string? LastTopRatedOrdering { get; private set; }

    /// <summary>How many searches were issued - the cost the adoption path is supposed to stop paying once it succeeds.</summary>
    public int SearchCount { get; private set; }

    private FakeVideoGameReferenceClient(List<VideoGameSearchResult> searchResults, string providerKey, IReadOnlyList<string> ratingSources)
    {
        _searchResults = searchResults;
        ProviderKey = providerKey;
        DisplayName = providerKey;
        SupportedRatingSources = ratingSources;
    }

    public static FakeVideoGameReferenceClient Empty(string providerKey = RatingSourceCatalog.Igdb, IReadOnlyList<string>? ratingSources = null) =>
        new([], providerKey, ratingSources ?? DefaultSourcesFor(providerKey));

    public static FakeVideoGameReferenceClient WithSearchResults(params VideoGameSearchResult[] results) =>
        new([.. results], RatingSourceCatalog.Igdb, DefaultSourcesFor(RatingSourceCatalog.Igdb));

    public static FakeVideoGameReferenceClient WithSearchResults(string providerKey, params VideoGameSearchResult[] results) =>
        new([.. results], providerKey, DefaultSourcesFor(providerKey));

    /// <summary>
    /// What the provider holds under exactly the queried title. Empty by default, so a test that only sets up
    /// search results exercises the widening path - the real clients answer this way for the case that path
    /// exists for (the two catalogues spell the work differently).
    /// </summary>
    public List<VideoGameSearchResult> ExactTitleResults { get; } = [];

    /// <summary>How many exact-title lookups were issued, counted separately from the relevance searches.</summary>
    public int ExactTitleSearchCount { get; private set; }

    /// <summary>
    /// What the provider answers to one *specific* query, for the tests about the adoption ladder's widening.
    /// A real provider's relevance search is punctuation-sensitive in ways that decide whether a game is
    /// found at all (IGDB answers "NieR:Automata" with one unrelated project and "NieR Automata" with the
    /// game), which a fake returning the same list whatever it is asked cannot express. Anything not listed
    /// here falls back to the fixed results, so every test that predates this behaves exactly as before.
    /// </summary>
    public Dictionary<string, List<VideoGameSearchResult>> SearchResultsByQuery { get; } = new(StringComparer.Ordinal);

    /// <summary>Every query the provider was asked, in order - what proves which rungs of the ladder ran.</summary>
    public List<string> Queries { get; } = [];

    /// <summary>Games reachable by <see cref="FindGameByIdentifierAsync"/>, keyed by id or page slug.</summary>
    public Dictionary<string, VideoGameSearchResult> Identifiers { get; } = new(StringComparer.Ordinal);

    public Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        SearchCount++;
        Queries.Add(title);
        return Task.FromResult<IReadOnlyList<VideoGameSearchResult>>(
            SearchResultsByQuery.TryGetValue(title, out var forQuery) ? forQuery : _searchResults);
    }

    /// <summary>
    /// The catalogue the substring rung filters, so a test states what the provider *holds* and lets the
    /// containment rule decide - the same thing the real query does server-side.
    /// </summary>
    public List<VideoGameSearchResult> Catalogue { get; } = [];

    /// <summary>How many substring queries were issued - it is the last resort, so mostly this should be 0.</summary>
    public int ContainsSearchCount { get; private set; }

    public Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default)
    {
        ContainsSearchCount++;
        return Task.FromResult<IReadOnlyList<VideoGameSearchResult>>(
            Catalogue.Where(game => words.All(word => game.Title.Contains(word, StringComparison.OrdinalIgnoreCase))).ToList());
    }

    public Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default)
    {
        IdentifierLookupCount++;
        return Task.FromResult(Identifiers.GetValueOrDefault(identifier));
    }

    /// <summary>How many pasted-address lookups were issued, counted apart from the two search shapes.</summary>
    public int IdentifierLookupCount { get; private set; }

    public Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
    {
        ExactTitleSearchCount++;
        Queries.Add(title);
        return Task.FromResult<IReadOnlyList<VideoGameSearchResult>>(
            ExactTitleResults.Where(r => string.Equals(r.Title, title, StringComparison.OrdinalIgnoreCase)).ToList());
    }

    public Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));

    public Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        LastTopRatedOrdering = ratingSource;
        return Task.FromResult(TopRatedPages.GetValueOrDefault(page, []));
    }

    private static IReadOnlyList<string> DefaultSourcesFor(string providerKey) => providerKey == RatingSourceCatalog.Rawg
        ? [RatingSourceCatalog.Rawg, RatingSourceCatalog.Metacritic]
        : [RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic];
}
