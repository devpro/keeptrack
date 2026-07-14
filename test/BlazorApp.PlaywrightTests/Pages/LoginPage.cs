using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The login page itself is OAuth-popup-only and cannot be driven by Playwright (see the e2e plan) - this
/// page object exists only so <c>AuthSmokeTest</c> can assert an anonymous visit lands here, not to sign in.
/// </summary>
public class LoginPage(IPage page) : PageBase(page)
{
    protected override string? PageTitle => "Login - Keeptrack";

    public override async Task WaitForReadyAsync()
    {
        // ASP.NET routing is case-insensitive server-side, so an unauthenticated redirect actually lands on
        // "/Account/Login" (RedirectToLogin.razor's route casing), not the all-lowercase "/account/login"
        // used elsewhere as a plain link href - confirmed against a real run.
        await Assertions.Expect(Page).ToHaveURLAsync(new Regex("/account/login", RegexOptions.IgnoreCase));
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new() { Name = "Continue with GitHub" })).ToBeVisibleAsync();
    }
}
