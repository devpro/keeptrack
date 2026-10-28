using Keeptrack.Common.Hosting.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.BlazorApp.Components.Account.Controllers;

public record LocalSignInRequest(string? Email, string? Role, string? ReturnUrl = null);

/// <summary>
/// Password-less sign-in for isolated environments and tests (see docs/authentication.md), never registered in Firebase mode.
/// </summary>
/// <remarks>
/// A JSON body, like Firebase's callback, so a cross-site form cannot post here without a CORS preflight.
/// </remarks>
[ApiController]
[Route("auth")]
[AuthenticationMode(AuthenticationMode.Local)]
public class LocalAuthenticationController(LocalTokenIssuer tokenIssuer) : AuthenticationControllerBase
{
    private static readonly string[] s_roles = ["member", "admin"];

    [HttpPost("local")]
    public async Task<IActionResult> SignIn([FromBody] LocalSignInRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest("Missing email");
        }

        var role = string.IsNullOrEmpty(request.Role) ? null : request.Role;
        if (role is not null && !s_roles.Contains(role))
        {
            return BadRequest("Unknown role");
        }

        var claims = LocalTokenIssuer.ClaimsFor(request.Email, role);
        var token = tokenIssuer.Issue(claims, DateTimeOffset.UtcNow, AuthenticationSettings.SessionLifetime);
        await SignInAsync((string)claims["sub"], claims, token);

        return Ok(new { redirect = ResolveReturnUrl(request.ReturnUrl) });
    }
}
