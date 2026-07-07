using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

internal sealed class FakeOpenLibraryClient : IOpenLibraryClient
{
    private readonly List<OpenLibrarySearchResult> _searchResults;

    public Dictionary<string, OpenLibraryBookDetails> Details { get; } = new();

    /// <summary>The author passed to the most recent <see cref="SearchBooksAsync"/> call, for assertions.</summary>
    public string? LastSearchAuthor { get; private set; }

    private FakeOpenLibraryClient(List<OpenLibrarySearchResult> searchResults) => _searchResults = searchResults;

    public static FakeOpenLibraryClient Empty() => new([]);

    public static FakeOpenLibraryClient WithSearchResults(params OpenLibrarySearchResult[] results) => new([.. results]);

    public Task<IReadOnlyList<OpenLibrarySearchResult>> SearchBooksAsync(string title, int? year, string? author = null, CancellationToken cancellationToken = default)
    {
        LastSearchAuthor = author;
        return Task.FromResult<IReadOnlyList<OpenLibrarySearchResult>>(_searchResults);
    }

    public Task<OpenLibraryBookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));
}
