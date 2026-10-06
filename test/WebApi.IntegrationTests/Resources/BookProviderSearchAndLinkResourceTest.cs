using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises the multi-provider search and link HTTP flow (<c>GET .../search</c>, <c>POST .../link</c>) against a real provider.
/// It is the one place in this suite proving the admin search and link through the registry reaches a live book provider end to end.
/// A fixed, well-known real title (not a GUID) makes the search return a match, the tradeoff the Playwright smoke tests accept for the other media types.
/// <para>
/// It runs against two providers, since whether a third party is up is the one thing this test can't control.
/// Google Books is the deployment default (<c>ReferenceData:BookProvider</c>), the provider a real search reaches, and BnF is keyless and quota-free.
/// A case whose provider is unreachable skips (see the 502 helpers below) instead of failing the build,
/// so this stays green when a provider is down and proves the path whenever one is up.
/// Open Library is not a case, being the slowest endpoint here even when healthy (see docs/providers.md), and covering the registry twice is enough.
/// </para>
/// </summary>
public class BookProviderSearchAndLinkResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string Title = "The Hobbit";
    private const string Author = "J.R.R. Tolkien";

    [Theory]
    [InlineData("googlebooks")]
    [InlineData("bnf")]
    public async Task SearchThenLink_ResolvesARealBook(string provider)
    {
        await Authenticate();

        var created = await CreateAsync("/api/books", new BookDto { Title = Title, Author = Author });

        var results = await GetThroughLiveProviderAsync<List<ReferenceSearchResultDto>>(
            $"/api/reference-data/search?type=Book&title={Uri.EscapeDataString(Title)}&creator={Uri.EscapeDataString(Author)}&provider={provider}",
            provider);

        results.Should().NotBeEmpty();

        await PostNoContentThroughLiveProviderAsync("/api/reference-data/link", new LinkReferenceRequestDto
        {
            Type = ReferenceItemType.Book,
            Title = Title,
            ExternalId = results[0].ExternalId,
            Provider = provider
        }, provider);

        var linked = await GetAsync<BookDto>($"/api/books/{created.Id}");
        linked.ReferenceId.Should().NotBeNullOrEmpty();

        // Linking creates the shared reference document, so its id is known only here, and it is registered for removal, this test being why it exists in the test database.
        // The author's person_reference stays: deduplicated by provider id, it is reused rather than re-created, and nothing identifies it as this test's.
        TrackDocument("book_reference", linked.ReferenceId);
    }
}
