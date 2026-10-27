using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class BookDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    public ILocator AuthorInput => Page.GetByTestId("author-input");

    public ILocator SeriesInput => Page.GetByTestId("series-input");

    /// <summary>
    /// Selects one of the book provider buttons ("Google Books", "Open Library", "BnF") before searching, books having several registered providers.
    /// Exact match since display names are short and otherwise unambiguous on this page.
    /// </summary>
    public async Task SelectProviderAsync(string displayName) =>
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = displayName, Exact = true }).ClickAsync();
}
