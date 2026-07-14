using System.Threading.Tasks;
using Keeptrack.BlazorApp.E2eTests.Hosting;
using Keeptrack.BlazorApp.E2eTests.Pages;
using Keeptrack.BlazorApp.E2eTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.E2eTests.Smoke;

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

        var list = await new ListPage(Page, "/books", "Books").OpenAsync();
        await list.ClickAddAsync();
        await list.FillAsync("Title", ReferenceFixtureZipBuilder.BookTitle);
        await list.FillAsync("Author", ReferenceFixtureZipBuilder.BookAuthor);
        await list.SaveNewAsync();
        await Assertions.Expect(list.Row(ReferenceFixtureZipBuilder.BookTitle)).ToBeVisibleAsync();

        await list.OpenItemAsync(ReferenceFixtureZipBuilder.BookTitle);
        var detail = await new BookDetailPage(Page).WaitForReadyAsync();

        await detail.ClickCheckReferenceMatchAsync();

        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookTitle);
        await Assertions.Expect(detail.FieldInput("Author")).ToHaveValueAsync(ReferenceFixtureZipBuilder.BookAuthor);
        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", ReferenceFixtureZipBuilder.BookImageUrl);

        await Page.GotoAsync("/books");
        await list.WaitForReadyAsync();
        await list.DeleteAsync(ReferenceFixtureZipBuilder.BookTitle);
    }
}
