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
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await DetailPageBase.SetFieldAsync(detail.SeriesInput, Series);

        // Round-tripping via the list (rather than a raw page reload) proves the edit persisted server-side just as well -
        // BookDetail.razor re-fetches via GetOneAsync on every navigation to it -
        // while staying on Blazor's enhanced (SPA) navigation throughout, which a raw reload would drop out of.
        list = await detail.OpenBooksAsync();
        await list.OpenItemAsync(title);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.SeriesInput).ToHaveValueAsync(Series);

        list = await detail.OpenBooksAsync();
        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
