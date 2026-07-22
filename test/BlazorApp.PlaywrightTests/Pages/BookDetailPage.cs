using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class BookDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    public ILocator AuthorInput => Page.GetByTestId("author-input");

    public ILocator SeriesInput => Page.GetByTestId("series-input");

    /// <summary>
    /// Book is the one reference-linked type with more than one registered provider - selects one of the
    /// provider buttons (e.g. "Google Books", "Open Library", "BnF") before searching. Exact match since
    /// display names are short and otherwise unambiguous on this page.
    /// </summary>
    public async Task SelectProviderAsync(string displayName) =>
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = displayName, Exact = true }).ClickAsync();
}
