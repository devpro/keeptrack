using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class HomePage(IPage page) : PageBase(page)
{
    protected override string? PageTitle => "Keeptrack";

    /// <summary>
    /// The one direct <c>GotoAsync</c> entry point - every other page is reached via a <see cref="PageBase"/>
    /// nav-link <c>Open&lt;X&gt;Async()</c> helper instead, matching <c>todo-blazor</c>'s own
    /// <c>HomePage.NavigateToAsync</c> shape.
    /// </summary>
    public async Task<HomePage> OpenAsync()
    {
        await Page.GotoAsync("/");
        await WaitForReadyAsync();
        return this;
    }
}
