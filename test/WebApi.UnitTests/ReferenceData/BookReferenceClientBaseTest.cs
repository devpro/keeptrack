using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The search policy every book provider shares - which query is attempted, in what order, and what happens
/// when one comes back empty. Tested once here against a recording fake rather than three times over three
/// providers' wire formats: the ordering IS the shared algorithm, and each provider's own test then only has
/// to prove it builds the right query string (see <c>OpenLibraryClientTest</c>/<c>BnfClientTest</c>).
/// </summary>
[Trait("Category", "UnitTests")]
public class BookReferenceClientBaseTest
{
    /// <summary>
    /// Records every call the policy makes, in order, and returns whatever each query was primed with.
    /// </summary>
    private sealed class RecordingBookClient(
        IReadOnlyList<BookSearchResult>? isbnResults = null,
        IReadOnlyList<BookSearchResult>? titleWithAuthorResults = null,
        IReadOnlyList<BookSearchResult>? titleOnlyResults = null) : BookReferenceClientBase
    {
        public override string ProviderKey => "recording";

        public override string DisplayName => "Recording";

        public List<string> Calls { get; } = [];

        protected override Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken)
        {
            Calls.Add($"isbn:{isbn}");
            return Task.FromResult(isbnResults ?? []);
        }

        protected override Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken)
        {
            Calls.Add(author is null ? $"title:{title}" : $"title:{title}+author:{author}");
            return Task.FromResult((author is null ? titleOnlyResults : titleWithAuthorResults) ?? []);
        }

        public override Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
            Task.FromResult<BookDetails?>(null);
    }

    private static IReadOnlyList<BookSearchResult> OneResult(string id) => [new BookSearchResult(id, "A Book", 1997, "An Author", null)];

    [Fact]
    public async Task SearchBooksAsync_SearchesByIsbnAloneAndStopsThere_WhenTheIsbnMatches()
    {
        // an ISBN identifies one edition exactly, so a hit beats anything a fuzzy title match could produce -
        // no title query should even be issued
        var client = new RecordingBookClient(isbnResults: OneResult("by-isbn"));

        var results = await client.SearchBooksAsync("Ignored Title", 1997, "Ignored Author", "9782265002104", TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("by-isbn");
        client.Calls.Should().ContainSingle().Which.Should().Be("isbn:9782265002104");
    }

    [Fact]
    public async Task SearchBooksAsync_WidensToTheTitleSearch_WhenTheIsbnMatchesNothing()
    {
        // the regression this whole change exists for: a catalogue that doesn't index an edition (BnF holds
        // no record for 9782265002104) must not report "no results" for a book it can find by title -
        // supplying an ISBN has to be never worse than leaving it blank
        var client = new RecordingBookClient(isbnResults: [], titleWithAuthorResults: OneResult("by-title"));

        var results = await client.SearchBooksAsync("A Book", 1997, "An Author", "9782265002104", TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("by-title");
        client.Calls.Should().Equal("isbn:9782265002104", "title:A Book+author:An Author");
    }

    [Fact]
    public async Task SearchBooksAsync_RetriesWithoutTheAuthor_WhenTheNarrowedSearchReturnsNothing()
    {
        var client = new RecordingBookClient(titleWithAuthorResults: [], titleOnlyResults: OneResult("by-title-only"));

        var results = await client.SearchBooksAsync("A Book", 1997, "Mismatched Author Text", cancellationToken: TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("by-title-only");
        client.Calls.Should().Equal("title:A Book+author:Mismatched Author Text", "title:A Book");
    }

    [Fact]
    public async Task SearchBooksAsync_FallsAllTheWayFromIsbnToTitleOnly_WhenBothNarrowingsMissed()
    {
        var client = new RecordingBookClient(isbnResults: [], titleWithAuthorResults: [], titleOnlyResults: OneResult("last-resort"));

        var results = await client.SearchBooksAsync("A Book", 1997, "An Author", "9782265002104", TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("last-resort");
        client.Calls.Should().Equal("isbn:9782265002104", "title:A Book+author:An Author", "title:A Book");
    }

    [Fact]
    public async Task SearchBooksAsync_NeverSearchesByIsbn_WhenNoneIsSupplied()
    {
        var client = new RecordingBookClient(titleWithAuthorResults: OneResult("by-title"));

        await client.SearchBooksAsync("A Book", 1997, "An Author", cancellationToken: TestContext.Current.CancellationToken);

        client.Calls.Should().ContainSingle().Which.Should().Be("title:A Book+author:An Author");
    }

    /// <summary>
    /// A widening step only ever fires on an EMPTY result - never to "improve on" results already found,
    /// which would replace an exact-identifier match with fuzzy ones.
    /// </summary>
    [Fact]
    public async Task SearchBooksAsync_DoesNotWiden_WhenTheNarrowSearchAlreadyFoundSomething()
    {
        var client = new RecordingBookClient(titleWithAuthorResults: OneResult("narrow-hit"), titleOnlyResults: OneResult("wide-hit"));

        var results = await client.SearchBooksAsync("A Book", 1997, "An Author", cancellationToken: TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("narrow-hit");
        client.Calls.Should().ContainSingle();
    }
}
