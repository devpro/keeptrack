using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>Same shape as <see cref="FakeBookReferenceClient"/>, just the second registered provider.</summary>
internal sealed class FakeBnfClient : IBookReferenceClient
{
    private readonly List<BookSearchResult> _searchResults;

    public string ProviderKey => "bnf";

    public string DisplayName => "BnF";

    public Dictionary<string, BookDetails> Details { get; } = new();

    public string? LastSearchAuthor { get; private set; }

    public string? LastSearchIsbn { get; private set; }

    private FakeBnfClient(List<BookSearchResult> searchResults) => _searchResults = searchResults;

    public static FakeBnfClient Empty() => new([]);

    public static FakeBnfClient WithSearchResults(params BookSearchResult[] results) => new([.. results]);

    public Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default)
    {
        LastSearchAuthor = author;
        LastSearchIsbn = isbn;
        return Task.FromResult<IReadOnlyList<BookSearchResult>>(_searchResults);
    }

    public Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Details.GetValueOrDefault(externalId));
}
