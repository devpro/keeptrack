using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// One page object for all inventory list pages, which the same <c>InventoryList</c> component renders.
/// </summary>
public class ListPage(IPage page, string route, string title) : PageBase(page)
{
    /// <summary>
    /// Direct navigation for a test that needn't start from Home,
    /// where every other page object is reached through a <see cref="PageBase"/> nav-link <c>Open&lt;X&gt;Async()</c> helper.
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
    /// The item row containing <paramref name="itemTitle"/>, scoping the delete action to one row, since every row repeats the same "Delete" label.
    /// </summary>
    public ILocator Row(string itemTitle) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = itemTitle });

    /// <summary>
    /// Asserts a row's wide thumbnail carries <paramref name="src"/>, the cover a detail page was just given, seen from the list.
    /// <para>
    /// Re-read rather than waited for (see <see cref="PageBase.ExpectWithReloadAsync"/>):
    /// the detail page saves by having the <i>server</i> PUT the item over its circuit, which the browser never sees.
    /// A list rendered while that save is in flight shows the item as it was and never updates, so waiting longer is only a timeout, a row stuck on its letter placeholder.
    /// </para>
    /// </summary>
    public Task ExpectRowThumbnailAsync(string itemTitle, string src) =>
        ExpectWithReloadAsync(() => Assertions.Expect(Row(itemTitle).Locator(".kt-item-thumb.wide img")).ToHaveAttributeAsync("src", src));

    /// <summary>
    /// The first state-changing click after a fresh page load (see <see cref="PageBase.ClickUntilAsync"/> for why this one, not every click, retries until visible).
    /// </summary>
    public async Task ClickAddAsync()
        => await ClickUntilAsync(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add" }), Page.Locator(".kt-form-card"));

    /// <summary>
    /// <paramref name="testId"/> is the field's <c>data-testid</c> ("title-input", "author-input").
    /// The add form's fields are plain sibling <c>&lt;label&gt;</c> and <c>&lt;input&gt;</c> pairs with no <c>for</c> and <c>id</c> association,
    /// which <c>GetByLabel</c> can't resolve.
    /// </summary>
    public async Task FillAsync(string testId, string value) => await Page.GetByTestId(testId).FillAsync(value);

    /// <summary>
    /// The video game and playlist Add forms use a bare <c>placeholder="Title"</c> input with no <c>&lt;label&gt;</c>,
    /// which <c>GetByPlaceholder</c> resolves uniquely without a <c>data-testid</c>.
    /// </summary>
    public async Task FillByPlaceholderAsync(string placeholder, string value) => await Page.GetByPlaceholder(placeholder).FillAsync(value);

    public async Task SaveNewAsync() => await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Save", Exact = true }).ClickAsync();

    /// <summary>
    /// Clicks a <c>kt-toggle-btn</c> filter button until it reads back as active,
    /// the first-click-after-load prerender gap <see cref="ClickAddAsync"/> handles through <see cref="PageBase.ClickUntilAsync"/>.
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
    /// The confirm click is scoped to the modal, since every row's delete icon shares the accessible "Delete" name, and a page-level lookup would be ambiguous.
    /// </summary>
    public async Task DeleteAsync(string itemTitle)
    {
        await Row(itemTitle).GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete" }).ClickAsync();
        await Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Delete", Exact = true }).ClickAsync();
    }

    /// <summary>
    /// Navigates to an item's detail page by clicking its title link.
    /// The caller constructs the typed detail page object it needs (<see cref="BookDetailPage"/>),
    /// since a generic list page doesn't know which detail page belongs to which item type.
    /// </summary>
    public async Task OpenItemAsync(string itemTitle)
        => await Page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = itemTitle, Exact = true }).ClickAsync();
}
