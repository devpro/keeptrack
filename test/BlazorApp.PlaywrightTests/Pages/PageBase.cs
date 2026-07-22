using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Sidebar navigation locators and typed <c>Open&lt;X&gt;Async()</c> helpers that return the next page object.
/// </summary>
/// <remarks>
/// <see cref="PageTitle"/> is null by default because only <c>Home.razor</c>/<c>Login.razor</c>/<c>Error.razor</c> set their own <c>&lt;PageTitle&gt;</c> -
/// every list/detail page has no title convention to assert at all, confirmed against a real run:
/// clicking a link *inside* an already-interactive <c>@rendermode InteractiveServer</c> component (e.g. a list row's title link)
/// takes a different client-side navigation path than a sidebar <c>NavLink</c> click and resets <c>document.title</c> to blank
/// when the destination has no <c>PageTitle</c> of its own, whereas sidebar navigation leaves whatever title was last set untouched.
/// Rather than fight that real (if surprising) behavior, only the three pages that genuinely own a title override this.
/// </remarks>
public abstract class PageBase(IPage page)
{
    protected IPage Page { get; } = page;

    protected virtual string? PageTitle => null;

    public virtual async Task WaitForReadyAsync()
    {
        if (PageTitle is not null)
        {
            await Assertions.Expect(Page).ToHaveTitleAsync(PageTitle);
        }
        await Assertions.Expect(Page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
    }

    /// <summary>
    /// Waits for <paramref name="expectedResult"/> to appear, re-clicking <paramref name="trigger"/> if it hasn't within a short window.
    /// Blazor Server prerenders (static SSR) before its SignalR circuit connects and wires up <c>@onclick</c> handlers -
    /// so the very first <c>@onclick</c>-driven click after a page becomes interactive can land in that gap and silently do nothing,
    /// even though the page's "loading resolved" signal (itself baked into the same prerendered payload) already reads ready.
    /// Confirmed with a real flaky run: adding artificial slowmo made it reliable, which is itself evidence of a genuine race rather than a code bug.
    /// This is a bounded, no-blind-sleep mitigation for exactly that - plain link-based navigation (<see cref="NavigateAsync{TPage}"/>) doesn't need it,
    /// since Blazor's enhanced navigation intercepts anchor clicks independently of the interactive circuit.
    /// </summary>
    protected static async Task ClickUntilAsync(ILocator trigger, ILocator expectedResult, int maxAttempts = 5)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            await trigger.ClickAsync();
            try
            {
                await Assertions.Expect(expectedResult).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 2000 });
                return;
            }
            catch (PlaywrightException) when (attempt < maxAttempts)
            {
            }
        }
    }

    /// <summary>
    /// The sidebar (<c>NavMenu.razor</c>'s <c>nav.flex-column</c>) -
    /// scoping to it matters because Home's own CTA ("Go to my movies") also matches a plain substring role/name lookup for "Movies".
    /// </summary>
    private ILocator SidebarNav => Page.Locator("nav.flex-column");

    private async Task<TPage> NavigateAsync<TPage>(string linkName, TPage next) where TPage : PageBase
    {
        await SidebarNav.GetByRole(AriaRole.Link, new LocatorGetByRoleOptions { Name = linkName }).ClickAsync();
        await next.WaitForReadyAsync();
        return next;
    }

    public Task<HomePage> OpenHomeAsync() => NavigateAsync("Home", new HomePage(Page));

    public Task<QuickAddPage> OpenQuickAddAsync() => NavigateAsync("Quick add", new QuickAddPage(Page));

    public Task<WatchNextPage> OpenWatchNextAsync() => NavigateAsync("Watch next", new WatchNextPage(Page));

    public Task<WishlistPage> OpenWishlistAsync() => NavigateAsync("Wishlist", new WishlistPage(Page));

    public Task<ListPage> OpenBooksAsync() => NavigateAsync("Books", new ListPage(Page, "/books", "Books"));

    public Task<ListPage> OpenMoviesAsync() => NavigateAsync("Movies", new ListPage(Page, "/movies", "Movies"));

    public Task<ListPage> OpenAlbumsAsync() => NavigateAsync("Albums", new ListPage(Page, "/albums", "Albums"));

    public Task<ListPage> OpenPlaylistsAsync() => NavigateAsync("Playlists", new ListPage(Page, "/playlists", "Playlists"));

    public Task<ListPage> OpenTvShowsAsync() => NavigateAsync("TV shows", new ListPage(Page, "/tv-shows", "TV Shows"));

    public Task<ListPage> OpenVideoGamesAsync() => NavigateAsync("Video games", new ListPage(Page, "/video-games", "Video Games"));

    public Task<ListPage> OpenCarsAsync() => NavigateAsync("Cars", new ListPage(Page, "/cars", "Cars"));

    public Task<ListPage> OpenHousesAsync() => NavigateAsync("Houses", new ListPage(Page, "/houses", "Houses"));

    public Task<ListPage> OpenHealthAsync() => NavigateAsync("Health", new ListPage(Page, "/health", "Health"));

    public Task<ListPage> OpenCollectiblesAsync() => NavigateAsync("Collectibles", new ListPage(Page, "/collectibles", "Collectibles"));

    public Task<ListPage> OpenGearAsync() => NavigateAsync("Gear", new ListPage(Page, "/gear", "Gear"));

    public Task<HomePage> LogoutAsync() => NavigateAsync("Log out", new HomePage(Page));
}
