using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.E2eTests.Hosting;
using Keeptrack.BlazorApp.E2eTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.E2eTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class BookSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddEditAndDelete_BookThroughTheList()
    {
        SkipIfReadOnly();

        var title = $"E2e Smoke Book {Guid.NewGuid():N}";
        const string author = "E2e Smoke Author";
        const string series = "E2e Smoke Series";

        var list = await new ListPage(Page, "/books", "Books").OpenAsync();
        await list.ClickAddAsync();
        await list.FillAsync("Title", title);
        await list.FillAsync("Author", author);
        await list.SaveNewAsync();

        await Assertions.Expect(list.Row(title)).ToBeVisibleAsync();

        await list.OpenItemAsync(title);
        var detail = await new BookDetailPage(Page).WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await detail.SetFieldAsync("Series", series);
        await Page.ReloadAsync();
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.FieldInput("Series")).ToHaveValueAsync(series);

        await Page.GotoAsync("/books");
        await list.WaitForReadyAsync();
        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
