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
/// Exercises the actual multi-provider search+link HTTP flow (<c>GET .../search</c>, <c>POST .../link</c>)
/// against a real provider. <see cref="RefreshReferenceResourceTest"/> deliberately only exercises the
/// local-only "check for reference match" lookup, never Search/Link, so this is the one place in this suite
/// that proves the registry/enrichment-service path actually reaches a live book provider end to end.
/// A fixed, well-known real title (not a GUID) is used so the search genuinely returns a match - the same
/// tradeoff the Playwright smoke tests already accept for Movie/TvShow/VideoGame/Album.
/// <para>
/// Run against both providers CI holds credentials for, because the one thing this test cannot control is
/// whether a third party is up: it originally pinned Open Library alone, on the belief that keyless-and-free
/// meant reliable, and went red when its <c>search.json</c> degraded to 52s and then 503/504 - past
/// <c>AddBookProviderResilienceHandler</c>'s 40s total budget (the same degradation recorded in
/// docs/code-quality-findings.md, which is why its rating fallback is guarded elsewhere). Google Books is the
/// deployment default (<c>ReferenceData:BookProvider</c>), so it is the provider a real user's search actually
/// reaches; BnF is keyless and quota-free, and was answering in under a second while the other two were down.
/// A case whose provider is genuinely unreachable skips (see the 502 helpers below) instead of failing the
/// build, so this stays green when a provider is down and still proves the path whenever one is up.
/// Open Library is deliberately not a case: it is the slowest endpoint any provider here calls even when
/// healthy, and covering the registry twice is the point, not covering it three times.
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

        // linking is what creates the shared reference document, so its id only becomes knowable here -
        // registered rather than left behind, since this test is the reason it exists in the test database.
        // The author's person_reference is deliberately left alone: it's deduplicated by provider id, so it
        // is reused rather than re-created, and it has no back-reference identifying it as ours to remove.
        TrackDocument("book_reference", linked.ReferenceId);
    }
}
