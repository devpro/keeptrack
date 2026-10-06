using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The login page is OAuth-popup-only and can't be driven by Playwright, so this page object only lets <c>AuthSmokeTest</c> assert an anonymous visit lands here.
/// </summary>
public partial class LoginPage(IPage page) : PageBase(page)
{
    protected override string? PageTitle => "Login - Keeptrack";

    [GeneratedRegex("/account/login", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex AccountLoginRegex();

    protected override async Task AssertReadyAsync()
    {
        // ASP.NET routing is case-insensitive server-side, so an unauthenticated redirect actually lands on "/Account/Login" (RedirectToLogin.razor's route casing),
        // not the all-lowercase "/account/login" used elsewhere as a plain link href
        await Assertions.Expect(Page).ToHaveURLAsync(AccountLoginRegex());
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Continue with GitHub" })).ToBeVisibleAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Continue with Google" })).ToBeVisibleAsync();
    }
}
