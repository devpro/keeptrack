using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises the actual multi-provider search+link HTTP flow (<c>GET .../search</c>, <c>POST .../link</c>)
/// against a real provider - Open Library specifically, since it's free/keyless and has proven reliable in
/// practice, unlike Google Books (observed to occasionally return a transient 503 - see
/// docs/code-quality-findings.md) or BnF (whose own "and" query combination needed a client-side correctness
/// fix - see <c>BnfClientTest</c>). <see cref="RefreshReferenceResourceTest"/> deliberately only exercises
/// the local-only "check for reference match" lookup, never Search/Link, so this is the one place in this
/// suite that proves the registry/enrichment-service path actually reaches a live book provider end to end.
/// A fixed, well-known real title (not a GUID) is used so the search genuinely returns a match - the same
/// tradeoff the Playwright smoke tests already accept for Movie/TvShow/VideoGame/Album.
/// </summary>
public class BookProviderSearchAndLinkResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string Title = "The Hobbit";
    private const string Author = "J.R.R. Tolkien";

    [Fact]
    public async Task SearchThenLink_ResolvesARealBook_ThroughOpenLibrary()
    {
        await Authenticate();

        var created = await PostAsync("/api/books", new BookDto { Title = Title, Author = Author });

        try
        {
            var results = await GetAsync<List<ReferenceSearchResultDto>>(
                $"/api/reference-data/search?type=Book&title={Uri.EscapeDataString(Title)}&creator={Uri.EscapeDataString(Author)}&provider=openlibrary");

            results.Should().NotBeEmpty();

            await PostNoContentAsync("/api/reference-data/link", new LinkReferenceRequestDto
            {
                Type = ReferenceItemType.Book,
                Title = Title,
                ExternalId = results[0].ExternalId,
                Provider = "openlibrary"
            });

            var linked = await GetAsync<BookDto>($"/api/books/{created.Id}");
            linked.ReferenceId.Should().NotBeNullOrEmpty();
        }
        finally
        {
            await DeleteAsync($"/api/books/{created.Id}");
        }
    }
}
