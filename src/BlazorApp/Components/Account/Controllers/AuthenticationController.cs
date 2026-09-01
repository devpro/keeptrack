using System.Security.Claims;
using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.BlazorApp.Components.Account.Controllers;

public record TokenRequest(string IdToken, string? ReturnUrl = null);

[ApiController]
[Route("auth")]
public class AuthenticationController : ControllerBase
{
    [HttpPost("callback")]
    public async Task<IActionResult> Callback([FromBody] TokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.IdToken))
        {
            return BadRequest("Missing token");
        }

        FirebaseToken decoded;
        try
        {
            decoded = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(request.IdToken);
        }
        catch
        {
            return Unauthorized();
        }

        await SignInWithFirebaseTokenAsync(decoded, request.IdToken);

        return Ok(new { redirect = ResolveReturnUrl(request.ReturnUrl) });
    }

    /// <summary>
    /// Re-issues the cookie with a freshly-rotated Firebase ID token. Firebase tokens expire after ~1h while
    /// the auth cookie lives 8h, so the client (see <c>FirebaseSessionRefresh</c>) posts each auto-refreshed
    /// token here to keep the stored token current and stop API calls coming back 401 mid-session. This is
    /// only for refreshing an already-established session - establishing one from scratch stays on
    /// <c>/auth/callback</c>.
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] TokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.IdToken))
        {
            return BadRequest("Missing token");
        }

        if (User.Identity?.IsAuthenticated != true)
        {
            return Unauthorized();
        }

        FirebaseToken decoded;
        try
        {
            decoded = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(request.IdToken);
        }
        catch
        {
            return Unauthorized();
        }

        // Never let a valid token for a *different* Firebase user swap the identity behind an existing
        // cookie - a refresh must be for the same user the session was issued to.
        if (decoded.Uid != User.FindFirstValue(ClaimTypes.NameIdentifier))
        {
            return Unauthorized();
        }

        await SignInWithFirebaseTokenAsync(decoded, request.IdToken);

        return Ok();
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }

    private string ResolveReturnUrl(string? returnUrl)
        => ReturnUrlResolver.Resolve(returnUrl, Request.Host.Value ?? string.Empty, Url.IsLocalUrl);

    private async Task SignInWithFirebaseTokenAsync(FirebaseToken decoded, string idToken)
    {
        var claims = FirebaseClaimsBuilder.Build(decoded.Uid, decoded.Claims);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        var props = new AuthenticationProperties { IsPersistent = true };
        props.StoreTokens([
            new AuthenticationToken { Name = AuthenticationTokenHandler.FirebaseTokenName, Value = idToken }
        ]);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            props);
    }
}
