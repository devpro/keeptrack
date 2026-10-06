using System;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Sidebar navigation locators and typed <c>Open&lt;X&gt;Async()</c> helpers that return the next page object.
/// </summary>
/// <remarks>
/// <see cref="PageTitle"/> is null by default, since only <c>Home.razor</c>, <c>Login.razor</c> and <c>Error.razor</c> set their own <c>&lt;PageTitle&gt;</c>, and list and detail pages have no title to assert.
/// A link clicked inside an interactive component (a list row's title link) navigates differently from a sidebar <c>NavLink</c>, and blanks <c>document.title</c> when the destination has no <c>PageTitle</c>.
/// Sidebar navigation leaves the last title untouched, so only the three pages owning a title override this.
/// </remarks>
public abstract class PageBase(IPage page)
{
    protected IPage Page { get; } = page;

    protected virtual string? PageTitle => null;

    /// <summary>
    /// The page's own route, for a page whose content alone can't prove the browser got there.
    /// <para>
    /// The import sub-pages are why this exists.
    /// <c>/import</c> is a hub rendering a section per importer, each with its own level-1 heading and a link to the sub-page, so "the Amazon heading is visible" holds on the hub too.
    /// A sub-page object waiting only for that would consider itself ready on the hub, and the next steps would run against the hub's DOM, which has three file inputs.
    /// Waiting for the URL asserts the navigation happened, and costs nothing on a page already there.
    /// </para>
    /// </summary>
    protected virtual string? Route => null;

    /// <summary>
    /// Waits for this page to be up, <b>re-issuing the navigation once</b> if it never rendered.
    /// <para>
    /// A click can change the URL without ever swapping the content, which is not slowness: <c>GET /cars</c> answers 200 in about 200ms, the URL becomes <c>/cars</c>, and the DOM still shows Home seconds later.
    /// It happens when the circuit's WebSocket connects just before the click, the prerender-to-interactive gap <see cref="ClickUntilAsync(ILocator, ILocator, int)"/> exists for, reached through enhanced navigation rather than an <c>@onclick</c>.
    /// </para>
    /// <para>
    /// A reload is the honest retry: the browser is on the right URL, so it re-fetches the page the click asked for rather than clicking again and hoping.
    /// It runs only after the page failed to appear, and only stops a lost navigation from being reported as a broken page.
    /// </para>
    /// </summary>
    public async Task WaitForReadyAsync() => await ExpectWithReloadAsync(AssertReadyAsync);

    /// <summary>What "ready" means for this page, overridden per page and never called directly by a test.</summary>
    protected virtual async Task AssertReadyAsync()
    {
        if (Route is not null)
        {
            await Page.WaitForURLAsync($"**{Route}");
        }
        if (PageTitle is not null)
        {
            await Assertions.Expect(Page).ToHaveTitleAsync(PageTitle);
        }
        await Assertions.Expect(Page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
    }

    /// <summary>
    /// Runs <paramref name="assertion"/> and, if it fails, reloads the page and runs it once more.
    /// <para>
    /// For the two things a browser can't wait for.
    /// A navigation the client lost renders nothing however long the assertion waits (see <see cref="WaitForReadyAsync"/>).
    /// A detail page's save is a PUT the <i>server</i> issues over its circuit, invisible to the browser, so a list rendered while one is in flight shows the pre-save item and never updates.
    /// Re-reading is the only way to see it land, where a longer timeout would wait on a page that never changes.
    /// </para>
    /// </summary>
    protected async Task ExpectWithReloadAsync(Func<Task> assertion)
    {
        try
        {
            await assertion();
        }
        catch (PlaywrightException)
        {
            await Page.ReloadAsync();
            await assertion();
        }
    }

    /// <summary>
    /// Waits for <paramref name="expectedResult"/> to appear, re-clicking <paramref name="trigger"/> if it hasn't within a short window.
    /// Blazor Server prerenders (static SSR) before its SignalR circuit connects and wires up <c>@onclick</c> handlers.
    /// The first <c>@onclick</c> click after a page becomes interactive can land in that gap and do nothing, while the page's "loading resolved" signal, baked into the prerendered payload, already reads ready.
    /// This is a bounded mitigation with no blind sleep.
    /// Link navigation (<see cref="NavigateAsync{TPage}"/>) doesn't need it, since enhanced navigation intercepts anchor clicks independently of the circuit.
    /// </summary>
    protected static Task ClickUntilAsync(ILocator trigger, ILocator expectedResult, int maxAttempts = 5)
        => ClickUntilAsync(trigger, () => Assertions.Expect(expectedResult).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 2000 }), maxAttempts);

    /// <summary>
    /// The same mitigation for an effect a "wait until this locator is visible" check can't express (a card disappearing, a query-string navigation), supplied as the assertion itself.
    /// <para>
    /// Two things the caller owns, and both matter.
    /// The trigger must be safe to click twice, since it may be.
    /// And <paramref name="expected"/>'s own timeout must comfortably exceed how long the action takes.
    /// A re-click while a successful click is in flight lands on a control the page has disabled (Explore's busy guard) or removed (the exhausted ranking's "Load more"), failing on the click rather than on anything under test.
    /// Wait longer, retry fewer times.
    /// </para>
    /// </summary>
    protected static async Task ClickUntilAsync(ILocator trigger, Func<Task> expected, int maxAttempts = 5)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            await trigger.ClickAsync();
            try
            {
                await expected();
                return;
            }
            catch (PlaywrightException) when (attempt < maxAttempts)
            {
            }
        }
    }

    /// <summary>
    /// The sidebar (<c>NavMenu.razor</c>'s <c>nav.flex-column</c>), scoped since Home's call to action ("Go to my movies") also matches a substring lookup for "Movies".
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

    public Task<ImportPage> OpenImportAsync() => NavigateAsync("Import", new ImportPage(Page));

    public Task<ReferenceDataAdminPage> OpenAdminAsync() => NavigateAsync("Admin", new ReferenceDataAdminPage(Page));

    public Task<WatchNextPage> OpenWatchNextAsync() => NavigateAsync("Watch next", new WatchNextPage(Page));

    public Task<WishlistPage> OpenWishlistAsync() => NavigateAsync("Wishlist", new WishlistPage(Page));

    public Task<ExplorePage> OpenExploreAsync() => NavigateAsync("Explore", new ExplorePage(Page));

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
