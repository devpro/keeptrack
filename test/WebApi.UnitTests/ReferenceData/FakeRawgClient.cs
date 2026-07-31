using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

internal sealed class FakeRawgClient : IRawgClient
{
    private readonly List<RawgSearchResult> _searchResults;

    public Dictionary<string, RawgGameDetails> Details { get; } = new();

    /// <summary>One page of Explore discovery results, keyed by page number - empty pages end the paging loop.</summary>
    public Dictionary<int, IReadOnlyList<RawgTopRatedItem>> TopRatedPages { get; } = new();

    /// <summary>The rating source the last <see cref="GetTopRatedGamesAsync"/> call asked RAWG to order by.</summary>
    public string? LastTopRatedOrdering { get; private set; }

    private FakeRawgClient(List<RawgSearchResult> searchResults) => _searchResults = searchResults;

    public static FakeRawgClient Empty() => new([]);

    public static FakeRawgClient WithSearchResults(params RawgSearchResult[] results) => new([.. results]);

    public Task<IReadOnlyList<RawgSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RawgSearchResult>>(_searchResults);

    public Task<RawgGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));

    public Task<IReadOnlyList<RawgTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        LastTopRatedOrdering = ratingSource;
        return Task.FromResult(TopRatedPages.GetValueOrDefault(page, []));
    }
}
