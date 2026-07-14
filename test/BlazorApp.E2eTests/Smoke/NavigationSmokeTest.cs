using System.Threading.Tasks;
using Keeptrack.BlazorApp.E2eTests.Hosting;
using Keeptrack.BlazorApp.E2eTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.E2eTests.Smoke;

/// <summary>
/// Proves every page loads with its header and no error boundary - read-only safe, so this is the one class
/// that also runs under <c>E2E_READONLY</c>.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class NavigationSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    public static TheoryData<string, string> ListPages => new()
    {
        { "/books", "Books" },
        { "/movies", "Movies" },
        { "/albums", "Albums" },
        { "/playlists", "Playlists" },
        { "/tv-shows", "Tv Shows" },
        { "/video-games", "Video Games" },
        { "/cars", "Cars" },
        { "/houses", "Houses" }
    };

    [Theory]
    [MemberData(nameof(ListPages))]
    public async Task ListPage_Loads_WithHeaderAndNoErrorBoundary(string route, string title)
    {
        await new ListPage(Page, route, title).OpenAsync();
        await AssertNoErrorBoundaryAsync();
    }

    [Fact]
    public async Task Home_Loads()
    {
        await new HomePage(Page).OpenAsync();
        await AssertNoErrorBoundaryAsync();
    }

    [Fact]
    public async Task WatchNext_Loads_WithHeader()
    {
        await Page.GotoAsync("/watch-next");
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = "Watch next", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await AssertNoErrorBoundaryAsync();
    }

    [Fact]
    public async Task Wishlist_Loads_WithHeader()
    {
        await Page.GotoAsync("/wishlist");
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = "Wishlist", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await AssertNoErrorBoundaryAsync();
    }

    private async Task AssertNoErrorBoundaryAsync()
        => await Assertions.Expect(Page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
}
