using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The Explore discovery page (<c>/explore</c>): one suggestion card per stored catalogue entry, a tab per
/// discovery domain, per-card add/dismiss actions and an explicit "Load more".
/// </summary>
public class ExplorePage(IPage page) : PageBase(page)
{
    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Explore", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>
    /// One suggestion row. The detailed list is the default view and the only one these tests drive - the
    /// thumbnail view's card is covered by an empty Bootstrap <c>stretched-link</c>, which has no size of its
    /// own and so cannot be clicked, exactly as every other list-page smoke test finds.
    /// </summary>
    public ILocator Card(string title) => Cards.Filter(new LocatorFilterOptions { HasText = title });

    public ILocator Cards => Page.Locator(".kt-item-row");

    /// <summary>The "something went wrong" banner - asserted hidden, since the page swallows a failed add/dismiss into it.</summary>
    public ILocator ErrorAlert => Page.Locator(".alert-danger");

    /// <summary>
    /// How long to let a control's own server round trip (dismiss, load more, refresh) settle before treating
    /// the click as never having registered. Well past what an indexed catalogue read costs, because the cost
    /// of guessing short is a re-click on a control the page has meanwhile disabled or removed.
    /// </summary>
    private const float ServerActionTimeout = 10_000;

    private ILocator LoadMoreButton => Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Load more" });

    private ILocator Tab(string name) => Page.Locator(".kt-tabs").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = name, Exact = true });

    /// <summary>
    /// Switches domain tab. Confirmed on the query string rather than on a card: selecting a tab is a real
    /// navigation, so the URL changes the instant the handler runs - which is exactly the "did this click
    /// register?" signal the retry needs, and it can't be confused with the fetch that follows being slow
    /// (a second click there would push a second history entry and break back-navigation).
    /// </summary>
    public async Task SelectTabAsync(string name, Regex expectedUrl)
        => await ClickUntilAsync(Tab(name), () => Assertions.Expect(Page).ToHaveURLAsync(expectedUrl, new PageAssertionsToHaveURLOptions { Timeout = 2000 }));

    /// <summary>
    /// Dismisses a suggestion and waits for its card to go. Safe to re-click - dismissing is idempotent
    /// server-side - but the wait is long and the attempts few, because the button disables itself while the
    /// call is in flight (see <see cref="PageBase.ClickUntilAsync(ILocator, Func{Task}, int)"/>).
    /// </summary>
    public async Task DismissAsync(string title)
        => await ClickUntilAsync(
            Card(title).GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Dismiss" }),
            () => Assertions.Expect(Card(title)).ToBeHiddenAsync(new LocatorAssertionsToBeHiddenOptions { Timeout = ServerActionTimeout }),
            maxAttempts: 2);

    /// <summary>
    /// Adds a suggestion to the collection. Deliberately a plain click, never a retrying one: a second add
    /// would create a second item, which is precisely what
    /// <see cref="PageBase.ClickUntilAsync(ILocator, ILocator, int)"/> must not be pointed at.
    /// </summary>
    public async Task AddAsync(string title)
        => await Card(title).GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Add to my collection" }).ClickAsync();

    /// <summary>Appends the next page below the current cards, waiting for <paramref name="expectedCardTitle"/> to arrive.</summary>
    public async Task LoadMoreAsync(string expectedCardTitle)
        => await ClickUntilAsync(
            LoadMoreButton,
            () => Assertions.Expect(Card(expectedCardTitle)).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = ServerActionTimeout }),
            maxAttempts: 2);

    /// <summary>Re-fetches the active tab from scratch - the page's own "↻ Refresh" control.</summary>
    public async Task RefreshAsync(string expectedCardTitle)
        => await ClickUntilAsync(
            Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Refresh" }),
            () => Assertions.Expect(Card(expectedCardTitle)).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = ServerActionTimeout }),
            maxAttempts: 2);

    public Task ExpectNoLoadMoreAsync() => Assertions.Expect(LoadMoreButton).ToBeHiddenAsync();
}
