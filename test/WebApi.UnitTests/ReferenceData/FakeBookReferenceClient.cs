using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

internal sealed class FakeBookReferenceClient : IBookReferenceClient
{
    private readonly List<BookSearchResult> _searchResults;

    public string ProviderKey => "openlibrary";

    public string DisplayName => "Open Library";

    public Dictionary<string, BookDetails> Details { get; } = new();

    /// <summary>The author passed to the most recent <see cref="SearchBooksAsync"/> call, for assertions.</summary>
    public string? LastSearchAuthor { get; private set; }

    /// <summary>The ISBN passed to the most recent <see cref="SearchBooksAsync"/> call, for assertions.</summary>
    public string? LastSearchIsbn { get; private set; }

    private FakeBookReferenceClient(List<BookSearchResult> searchResults) => _searchResults = searchResults;

    public static FakeBookReferenceClient Empty() => new([]);

    public static FakeBookReferenceClient WithSearchResults(params BookSearchResult[] results) => new([.. results]);

    public Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default)
    {
        LastSearchAuthor = author;
        LastSearchIsbn = isbn;
        return Task.FromResult<IReadOnlyList<BookSearchResult>>(_searchResults);
    }

    public Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));
}
