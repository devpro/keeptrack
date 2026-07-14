using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// One page object for all ten inventory list pages (Books, Movies, Albums, Playlists, TV shows, Video
/// games, Cars, Houses, plus Wishlist/Watch next's simpler card layout is covered separately) - they are
/// all rendered by the same <c>InventoryList</c> component, so a single parameterized page object covers
/// every one of them rather than ten near-identical copies (see CLAUDE.md's "no duplicated algorithms"
/// quality bar and the e2e plan's "minimal code" requirement).
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

    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = title, Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>
    /// The table row containing <paramref name="itemTitle"/> - scoping edit/delete actions to a specific
    /// row, since every row repeats the same "Edit"/"Del" button labels.
    /// </summary>
    public ILocator Row(string itemTitle) => Page.Locator("table tbody tr", new() { HasText = itemTitle });

    /// <summary>
    /// The first state-changing click after a fresh page load - see <see cref="PageBase.ClickUntilAsync"/> for
    /// why this specifically (not every click) needs the retry-until-visible treatment.
    /// </summary>
    public async Task ClickAddAsync()
        => await ClickUntilAsync(Page.GetByRole(AriaRole.Button, new() { Name = "+ Add" }), Page.Locator(".kt-form-card"));

    /// <summary>
    /// <paramref name="testId"/> is the field's <c>data-testid</c> (e.g. "title-input"/"author-input") - the
    /// add form's fields are plain sibling <c>&lt;label&gt;</c>/<c>&lt;input&gt;</c> pairs with no <c>for</c>/
    /// <c>id</c> association, so <c>GetByLabel</c> structurally can't resolve them (confirmed against a real
    /// run: the "Title" field could never be found, every add-form fill silently timed out). Matches
    /// <c>todo-blazor</c>'s own convention of reaching for <c>data-testid</c> once role/label lookup proves
    /// unusable, not just fragile.
    /// </summary>
    public async Task FillAsync(string testId, string value) => await Page.GetByTestId(testId).FillAsync(value);

    public async Task SaveNewAsync() => await Page.GetByRole(AriaRole.Button, new() { Name = "Save", Exact = true }).ClickAsync();

    public async Task SearchAsync(string query)
    {
        var search = Page.GetByPlaceholder("Search…");
        await search.FillAsync(query);
        await search.PressAsync("Enter");
    }

    public async Task StartEditAsync(string itemTitle)
        => await ClickUntilAsync(Row(itemTitle).GetByRole(AriaRole.Button, new() { Name = "Edit" }), Page.Locator(".kt-modal"));

    public async Task SaveModalAsync() => await Page.GetByRole(AriaRole.Button, new() { Name = "Save", Exact = true }).ClickAsync();

    public async Task DeleteAsync(string itemTitle)
    {
        await Row(itemTitle).GetByRole(AriaRole.Button, new() { Name = "Del" }).ClickAsync();
        await Page.GetByRole(AriaRole.Button, new() { Name = "Delete", Exact = true }).ClickAsync();
    }

    /// <summary>
    /// Navigates to an item's own detail page by clicking its title link - the caller constructs whatever
    /// typed detail page object it needs afterward (e.g. <see cref="BookDetailPage"/>), since a generic list
    /// page has no business knowing which detail page type belongs to which item type.
    /// </summary>
    public async Task OpenItemAsync(string itemTitle)
        => await Page.GetByRole(AriaRole.Link, new() { Name = itemTitle, Exact = true }).ClickAsync();
}
