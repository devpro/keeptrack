using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

internal sealed class FakeRawgClient : IRawgClient
{
    private readonly List<RawgSearchResult> _searchResults;

    public Dictionary<string, RawgGameDetails> Details { get; } = new();

    private FakeRawgClient(List<RawgSearchResult> searchResults) => _searchResults = searchResults;

    public static FakeRawgClient Empty() => new([]);

    public static FakeRawgClient WithSearchResults(params RawgSearchResult[] results) => new([.. results]);

    public Task<IReadOnlyList<RawgSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<RawgSearchResult>>(_searchResults);

    public Task<RawgGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));
}
