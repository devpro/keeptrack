using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class BookSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddEditAndDelete_BookThroughTheList()
    {
        SkipIfReadOnly();

        var title = $"E2e Smoke Book {Guid.NewGuid():N}";
        const string Series = "E2e Smoke Series";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenBooksAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", title);
        await list.FillAsync("author-input", "E2e Smoke Author");
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/books");
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await DetailPageBase.SetFieldAsync(detail.SeriesInput, Series);

        // Round-tripping through the list proves the edit persisted server-side as well as a reload,
        // since BookDetail.razor re-fetches on every navigation, while staying on enhanced navigation.
        list = await detail.OpenBooksAsync();
        await list.OpenItemAsync(title);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.SeriesInput).ToHaveValueAsync(Series);

        list = await detail.OpenBooksAsync();
        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
