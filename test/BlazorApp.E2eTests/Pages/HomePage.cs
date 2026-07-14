using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.E2eTests.Pages;

public class HomePage(IPage page) : PageBase(page)
{
    public async Task<HomePage> OpenAsync()
    {
        await Page.GotoAsync("/");
        await Assertions.Expect(Page).ToHaveTitleAsync("Keeptrack");
        return this;
    }
}
