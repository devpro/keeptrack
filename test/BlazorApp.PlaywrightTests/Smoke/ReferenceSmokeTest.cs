using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// With <see cref="E2eFixture"/>'s synthetic book reference already imported, adding a book with the exact
/// matching title/author and clicking "check for reference match" must resolve it - a local Mongo lookup
/// only (<c>TryLinkExistingBookReferenceAsync</c>), never a real Open Library call, so this stays deterministic.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ReferenceSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
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
        await Assertions.Expect(list.Row(ReferenceFixtureZipBuilder.BookTitle)).ToBeVisibleAsync();

        await list.OpenItemAsync(ReferenceFixtureZipBuilder.BookTitle);
        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();

        await detail.ClickCheckReferenceMatchAsync();

        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookTitle);
        await Assertions.Expect(detail.AuthorInput).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookAuthor);
        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", ReferenceFixtureZipBuilder.BookImageUrl);

        list = await detail.OpenBooksAsync();
        await list.DeleteAsync(ReferenceFixtureZipBuilder.BookTitle);
    }
}
