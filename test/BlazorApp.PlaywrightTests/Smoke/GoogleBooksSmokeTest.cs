using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Verifies the Google Books provider specifically (Book's own add/edit/delete flow is already covered by
/// <see cref="BookSmokeTest"/>, which never links to any provider). Opt-in via
/// <c>GOOGLE_BOOKS_SMOKE_ENABLED</c>, unlike TMDB/RAWG/Discogs (hard-required for their own always-on smoke
/// tests) - Google Books has been observed to occasionally return a transient 503 (see
/// docs/code-quality-findings.md), and it's the newest/least-proven of the three registered book providers,
/// so this stays a deliberate, on-demand check rather than part of the default run.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class GoogleBooksSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private const string Title = "The Hobbit";
    private const string Author = "J.R.R. Tolkien";

    [Fact]
    public async Task AddLinkAndDelete_BookThroughGoogleBooks()
    {
        SkipIfReadOnly();
        Assert.SkipUnless(Environment.GetEnvironmentVariable("GOOGLE_BOOKS_SMOKE_ENABLED") == "true",
            "GOOGLE_BOOKS_SMOKE_ENABLED is not set; the Google Books provider smoke test is opt-in.");

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenBooksAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", Title);
        await list.FillAsync("author-input", Author);
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();
        var id = ExtractIdFromUrl(Page.Url);

        try
        {
            // Google Books is already the registered default (first in Program.cs), but select it
            // explicitly so this test still proves the right thing if that ever changes.
            await detail.SelectProviderAsync("Google Books");
            await detail.SearchAndLinkFirstResultAsync();

            await Assertions.Expect(detail.CoverImage.First).ToBeVisibleAsync();
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/books/{id}");
        }
    }
}
