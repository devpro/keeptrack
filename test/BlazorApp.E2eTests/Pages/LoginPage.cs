using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.E2eTests.Pages;

/// <summary>
/// The login page itself is OAuth-popup-only and cannot be driven by Playwright (see the e2e plan) - this
/// page object exists only so <c>AuthSmokeTest</c> can assert an anonymous visit lands here, not to sign in.
/// </summary>
public class LoginPage(IPage page) : PageBase(page)
{
    public async Task<LoginPage> WaitForReadyAsync()
    {
        await Assertions.Expect(Page).ToHaveURLAsync(new System.Text.RegularExpressions.Regex("/account/login"));
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new() { Name = "Continue with GitHub" })).ToBeVisibleAsync();
        return this;
    }
}
