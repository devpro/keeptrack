using System.Collections.Generic;
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

    public Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        SearchCount++;
        return Task.FromResult<IReadOnlyList<VideoGameSearchResult>>(_searchResults);
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
