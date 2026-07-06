using System.Security.Claims;
using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.BlazorApp.Components.Account.Controllers;

public record TokenRequest(string IdToken);

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

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, decoded.Uid),
            new(ClaimTypes.Name, decoded.Claims.TryGetValue("name", out var n) ? n.ToString()! : decoded.Uid),
            new(ClaimTypes.Email, decoded.Claims.TryGetValue("email", out var e) ? e.ToString()! : ""),
        };

        // Firebase custom claims (e.g. the admin "role" claim, set via the Firebase Admin SDK) land in
        // decoded.Claims like any other - copy them through so Blazor's own AuthorizeView/policy checks
        // (which run against this cookie principal, not the bearer token WebApi validates separately) see them too.
        if (decoded.Claims.TryGetValue("role", out var role))
        {
            claims.Add(new Claim("role", role.ToString()!));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        var props = new AuthenticationProperties { IsPersistent = true };
        props.StoreTokens([
            new AuthenticationToken { Name = AuthenticationTokenHandler.FirebaseTokenName, Value = request.IdToken }
        ]);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            props);

        return Ok(new { redirect = "/" });
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }
}
