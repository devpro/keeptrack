using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class HomePage(IPage page) : PageBase(page)
{
    protected override string? PageTitle => "Keeptrack";

    public async Task<HomePage> OpenAsync()
    {
        await Page.GotoAsync("/");
        await WaitForReadyAsync();
        return this;
    }
}
