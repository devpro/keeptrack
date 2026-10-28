using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.BlazorApp.Components.Account.Controllers;

/// <summary>
/// What every mode's sign-in shares once the identity is verified: the cookie, the API token it carries, the return URL and the logout.
/// Each mode derives one controller, and only the active mode's is registered (see <see cref="AuthenticationModeControllerFilter"/>).
/// </summary>
public abstract class AuthenticationControllerBase : ControllerBase
{
    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }

    protected string ResolveReturnUrl(string? returnUrl)
        => ReturnUrlResolver.Resolve(returnUrl, Request.Host.Value ?? string.Empty, Url.IsLocalUrl);

    protected async Task SignInAsync(string userId, IReadOnlyDictionary<string, object> tokenClaims, string apiToken)
    {
        var claims = SessionClaimsBuilder.Build(userId, tokenClaims);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        var props = new AuthenticationProperties { IsPersistent = true };
        props.StoreTokens([
            new AuthenticationToken { Name = AuthenticationTokenHandler.ApiTokenName, Value = apiToken }
        ]);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            props);
    }
}
