using System.Security.Claims;
using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.BlazorApp.Components.Account.Controllers;

public record TokenRequest(string IdToken, string? ReturnUrl = null);

[ApiController]
[Route("auth")]
[AuthenticationMode(AuthenticationMode.Firebase)]
public class FirebaseAuthenticationController : AuthenticationControllerBase
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

        await SignInAsync(decoded.Uid, decoded.Claims, request.IdToken);

        return Ok(new { redirect = ResolveReturnUrl(request.ReturnUrl) });
    }

    /// <summary>
    /// Re-issues the cookie with a freshly rotated Firebase ID token.
    /// Firebase tokens expire after about 1h while the auth cookie lives 8h,
    /// so the client (<c>FirebaseSessionRefresh</c>) posts each refreshed token here, or API calls would answer 401 mid-session.
    /// It only refreshes an established session, and establishing one stays on <c>/auth/callback</c>.
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

        // A valid token for a different Firebase user never swaps the identity behind an existing cookie, since a refresh must be for the session's own user.
        if (decoded.Uid != User.FindFirstValue(ClaimTypes.NameIdentifier))
        {
            return Unauthorized();
        }

        await SignInAsync(decoded.Uid, decoded.Claims, request.IdToken);

        return Ok();
    }
}
