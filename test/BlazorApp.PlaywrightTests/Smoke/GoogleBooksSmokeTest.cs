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
        // No author, and that is what makes this test deterministic rather than a saving of typing.
        // The provider picker lives inside InlineReferenceLinker, which BookDetail renders only while the book is unlinked, so a check-for-reference-match that links the book by itself leaves nothing to select a provider on.
        // TryAutoResolveBookAsync refuses to link without an author, since a title alone routinely names several works, so withholding one guarantees the check comes back unlinked and the picker is on screen.
        // Filled in, "The Hobbit" by "J.R.R. Tolkien" is precisely the input ConfirmedCreatorMatches links on sight, and SelectProviderAsync then waited 30s for a button that could never render.
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/books");

        await detail.ClickCheckReferenceMatchAsync();

        // Google Books is already the registered default (first in Program.cs), but select it
        // explicitly so this test still proves the right thing if that ever changes.
        await detail.SelectProviderAsync("Google Books");
        await detail.SearchAndLinkFirstResultAsync();

        await Assertions.Expect(detail.CoverImage.First).ToBeVisibleAsync();
    }
}
