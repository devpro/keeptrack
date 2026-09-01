using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// One PageObject for all inventory list pages - they are all rendered by the same <c>InventoryList</c> component.
/// </summary>
public class ListPage(IPage page, string route, string title) : PageBase(page)
{
    /// <summary>
    /// Direct-navigation convenience for a test that doesn't care about starting from Home - every other
    /// page object is reached via a <see cref="PageBase"/> nav-link <c>Open&lt;X&gt;Async()</c> helper.
    /// </summary>
    public async Task<ListPage> OpenAsync()
    {
        await Page.GotoAsync(route);
        await WaitForReadyAsync();
        return this;
    }

    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = title, Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>
    /// The item row containing <paramref name="itemTitle"/> - scoping the delete action to a specific row, since every row repeats the same "Delete" button label.
    /// </summary>
    public ILocator Row(string itemTitle) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = itemTitle });

    /// <summary>
    /// Asserts a row's wide thumbnail carries <paramref name="src"/> - the cover a detail page has just been given, seen from the list.
    /// <para>
    /// Re-read rather than merely waited for (see <see cref="PageBase.ExpectWithReloadAsync"/>): the detail page saves by having the <i>server</i> PUT the item over its own circuit, which the browser never sees, so a list rendered while that save is still in flight shows the item as it was and will never update itself.
    /// Waiting longer on a page that cannot change is not a wait, it is a timeout - observed as a row stuck on its letter placeholder.
    /// </para>
    /// </summary>
    public Task ExpectRowThumbnailAsync(string itemTitle, string src) =>
        ExpectWithReloadAsync(() => Assertions.Expect(Row(itemTitle).Locator(".kt-item-thumb.wide img")).ToHaveAttributeAsync("src", src));

    /// <summary>
    /// The first state-changing click after a fresh page load -
    /// see <see cref="PageBase.ClickUntilAsync"/> for why this specifically (not every click) needs the retry-until-visible treatment.
    /// </summary>
    public async Task ClickAddAsync()
        => await ClickUntilAsync(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add" }), Page.Locator(".kt-form-card"));

    /// <summary>
    /// <paramref name="testId"/> is the field's <c>data-testid</c> (e.g. "title-input"/"author-input") -
    /// the add form's fields are plain sibling <c>&lt;label&gt;</c>/<c>&lt;input&gt;</c> pairs with no <c>for</c>/ <c>id</c> association,
    /// so <c>GetByLabel</c> structurally can't resolve them (confirmed against a real run:
    /// the "Title" field could never be found, every add-form fill silently timed out).
    /// </summary>
    public async Task FillAsync(string testId, string value) => await Page.GetByTestId(testId).FillAsync(value);

    /// <summary>
    /// VideoGames' and Playlists' Add forms use a bare <c>placeholder="Title"</c> input with no <c>&lt;label&gt;</c> at all -
    /// <c>GetByPlaceholder</c> already resolves it uniquely, so no <c>data-testid</c> was needed there.
    /// </summary>
    public async Task FillByPlaceholderAsync(string placeholder, string value) => await Page.GetByPlaceholder(placeholder).FillAsync(value);

    public async Task SaveNewAsync() => await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Save", Exact = true }).ClickAsync();

    /// <summary>
    /// Clicks a <c>kt-toggle-btn</c> filter button until it reads back as active - the same
    /// first-click-after-load prerender gap <see cref="ClickAddAsync"/> mitigates via
    /// <see cref="PageBase.ClickUntilAsync"/>.
    /// </summary>
    public async Task ClickFilterUntilActiveAsync(ILocator filterButton)
        => await ClickUntilAsync(filterButton, Page.Locator("button.kt-toggle-btn.active"));

    public async Task SearchAsync(string query)
    {
        var search = Page.GetByPlaceholder("Search…");
        await search.FillAsync(query);
        await search.PressAsync("Enter");
    }

    /// <summary>
    /// The confirm click is scoped to the modal -
    /// every row's own delete icon shares the same accessible "Delete" name, so a page-level lookup would be ambiguous.
    /// </summary>
    public async Task DeleteAsync(string itemTitle)
    {
        await Row(itemTitle).GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete" }).ClickAsync();
        await Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete", Exact = true }).ClickAsync();
    }

    /// <summary>
    /// Navigates to an item's own detail page by clicking its title link -
    /// the caller constructs whatever typed detail page object it needs afterward (e.g. <see cref="BookDetailPage"/>),
    /// since a generic list page has no business knowing which detail page type belongs to which item type.
    /// </summary>
    public async Task OpenItemAsync(string itemTitle)
        => await Page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = itemTitle, Exact = true }).ClickAsync();
}
