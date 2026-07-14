using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.E2eTests.Pages;

/// <summary>
/// One page object for all ten inventory list pages (Books, Movies, Albums, Playlists, TV shows, Video
/// games, Cars, Houses, plus Wishlist/Watch next's simpler card layout is covered separately) - they are
/// all rendered by the same <c>InventoryList</c> component, so a single parameterized page object covers
/// every one of them rather than ten near-identical copies (see CLAUDE.md's "no duplicated algorithms"
/// quality bar and the e2e plan's "minimal code" requirement).
/// </summary>
public class ListPage(IPage page, string route, string title) : PageBase(page)
{
    public async Task<ListPage> OpenAsync()
    {
        await Page.GotoAsync(route);
        await WaitForReadyAsync();
        return this;
    }

    public async Task WaitForReadyAsync()
    {
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = title, Level = 1 })).ToBeVisibleAsync();
        await WaitForLoadingToResolveAsync(Page);
    }

    /// <summary>
    /// The table row containing <paramref name="itemTitle"/> - scoping edit/delete actions to a specific
    /// row, since every row repeats the same "Edit"/"Del" button labels.
    /// </summary>
    public ILocator Row(string itemTitle) => Page.Locator("table tbody tr", new() { HasText = itemTitle });

    public async Task ClickAddAsync() => await Page.GetByRole(AriaRole.Button, new() { Name = "+ Add" }).ClickAsync();

    public async Task FillAsync(string label, string value) => await Page.GetByLabel(label).FillAsync(value);

    public async Task SaveNewAsync() => await Page.GetByRole(AriaRole.Button, new() { Name = "Save", Exact = true }).ClickAsync();

    public async Task SearchAsync(string query)
    {
        var search = Page.GetByPlaceholder("Search…");
        await search.FillAsync(query);
        await search.PressAsync("Enter");
    }

    public async Task StartEditAsync(string itemTitle)
        => await Row(itemTitle).GetByRole(AriaRole.Button, new() { Name = "Edit" }).ClickAsync();

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
