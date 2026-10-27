using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// With <see cref="End2EndFixture"/>'s synthetic book reference imported, adding a book with the matching title and author and clicking "check for reference match" resolves it.
/// The local lookup (<c>TryLinkExistingBookReferenceAsync</c>) answers before any provider, so this stays deterministic.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ReferenceSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task CheckForReferenceMatch_ResolvesTheSeededBook()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenBooksAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", ReferenceFixtureZipBuilder.BookTitle);
        await list.FillAsync("author-input", ReferenceFixtureZipBuilder.BookAuthor);
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/books");

        await detail.ClickCheckReferenceMatchAsync();

        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookTitle);
        await Assertions.Expect(detail.AuthorInput).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookAuthor);
        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", ReferenceFixtureZipBuilder.BookImageUrl);

        list = await detail.OpenBooksAsync();
        await list.DeleteAsync(ReferenceFixtureZipBuilder.BookTitle);
    }
}
