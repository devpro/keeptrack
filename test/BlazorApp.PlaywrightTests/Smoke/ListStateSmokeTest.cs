using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Proves list state (search, filters) lives in the URL and survives leaving the list:
/// opening an item's detail page and navigating back must restore the exact filtered position instead of resetting to an unfiltered page 1.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public partial class ListStateSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [GeneratedRegex("[?&]search=")]
    private static partial Regex SearchRegex();

    [GeneratedRegex("[?&]favorite=true", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex FavoriteRegex();

    [Fact]
    public async Task Search_PersistsInUrl_AndSurvivesBackNavigationFromDetail()
    {
        SkipIfReadOnly();

        var title = $"E2e List State Book {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenBooksAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", title);
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();

        list = await detail.OpenBooksAsync();
        await list.SearchAsync(title);
        await Assertions.Expect(Page).ToHaveURLAsync(SearchRegex());
        await Assertions.Expect(list.Row(title)).ToBeVisibleAsync();

        await list.OpenItemAsync(title);
        await detail.WaitForReadyAsync();

        await Page.GoBackAsync();
        await list.WaitForReadyAsync();
        await Assertions.Expect(Page).ToHaveURLAsync(SearchRegex());
        await Assertions.Expect(Page.GetByPlaceholder("Search…")).ToHaveValueAsync(title);
        await Assertions.Expect(list.Row(title)).ToBeVisibleAsync();

        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }

    [Fact]
    public async Task FilterToggle_PersistsInUrl_AndTogglesBackOff()
    {
        var list = await (await new HomePage(Page).OpenAsync()).OpenMoviesAsync();
        var favoritesUrl = FavoriteRegex();
        var favoritesButton = Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "★ Favorites" });

        // The toggle-on click is this page load's first @onclick - see ClickUntilAsync's prerender-gap remarks.
        await list.ClickFilterUntilActiveAsync(favoritesButton);
        await Assertions.Expect(Page).ToHaveURLAsync(favoritesUrl);

        await favoritesButton.ClickAsync();
        await Assertions.Expect(Page).Not.ToHaveURLAsync(favoritesUrl);
        await list.WaitForReadyAsync();
    }
}
