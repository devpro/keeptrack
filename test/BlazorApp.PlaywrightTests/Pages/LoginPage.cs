using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.Testing.Shared.Authentication;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The Firebase login page is OAuth-popup-only and can't be driven by Playwright, so in Firebase mode this page object only lets <c>AuthSmokeTest</c> assert an anonymous visit lands here.
/// The local login form is driven for real.
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
        if (TestAuthentication.IsLocal)
        {
            await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Sign in" })).ToBeVisibleAsync();
            return;
        }

        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Continue with GitHub" })).ToBeVisibleAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Continue with Google" })).ToBeVisibleAsync();
    }

    /// <param name="role">The option label: "Free preview", "Member" or "Admin".</param>
    public async Task SignInLocallyAsync(string email, string role)
    {
        await Page.GetByLabel("Email").FillAsync(email);
        await Page.GetByLabel("Role").SelectOptionAsync(new SelectOptionValue { Label = role });
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Sign in" }).ClickAsync();
    }
}
