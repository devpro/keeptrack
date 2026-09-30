using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

internal sealed class FakeDiscogsClient : IDiscogsClient
{
    private readonly List<DiscogsSearchResult> _searchResults;

    public Dictionary<string, DiscogsAlbumDetails> Details { get; } = new();

    /// <summary>The artist passed to the most recent <see cref="SearchAlbumsAsync"/> call, for assertions.</summary>
    public string? LastSearchArtist { get; private set; }

    private FakeDiscogsClient(List<DiscogsSearchResult> searchResults) => _searchResults = searchResults;

    public static FakeDiscogsClient Empty() => new([]);

    public static FakeDiscogsClient WithSearchResults(params DiscogsSearchResult[] results) => new([.. results]);

    /// <summary>How many searches were issued - zero is what "the local reference answered" looks like.</summary>
    public int SearchCount { get; private set; }

    public Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsAsync(string title, int? year, string? artist = null, CancellationToken cancellationToken = default)
    {
        SearchCount++;
        LastSearchArtist = artist;
        return Task.FromResult<IReadOnlyList<DiscogsSearchResult>>(_searchResults);
    }

    public Task<DiscogsAlbumDetails?> GetAlbumDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));
}
