using System.Security.Claims;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Builds the cookie principal's claims from a verified token's own claims, whichever mode issued it.
/// </summary>
/// <remarks>
/// A pure function, like <see cref="ReturnUrlResolver"/>, so the "role" claim copy is tested without a real token or HTTP pipeline.
/// It is the one place the "role" claim (a Firebase custom claim, or the role picked on the local sign-in form) crosses into Blazor's cookie principal,
/// which <c>AuthorizeView</c> and policy checks run against.
/// The bearer token WebApi validates carries the same claim on its own path, and <c>AddJwtBearer</c>'s <c>MapInboundClaims = false</c> has no bearing on this copy.
/// The two are checked independently, or the UI can show the admin nav link while the same user's API calls answer 403.
/// </remarks>
public static class SessionClaimsBuilder
{
    /// <param name="uid">The verified token's subject, stamped as <see cref="ClaimTypes.NameIdentifier"/>.</param>
    /// <param name="tokenClaims">The verified token's own claims (<c>FirebaseToken.Claims</c>, or <c>LocalTokenIssuer.ClaimsFor</c>).</param>
    public static List<Claim> Build(string uid, IReadOnlyDictionary<string, object> tokenClaims)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, uid),
            new(ClaimTypes.Name, tokenClaims.TryGetValue("name", out var name) ? name.ToString()! : uid),
            new(ClaimTypes.Email, tokenClaims.TryGetValue("email", out var email) ? email.ToString()! : "")
        };

        if (tokenClaims.TryGetValue("role", out var role))
        {
            claims.Add(new Claim("role", role.ToString()!));
        }

        return claims;
    }
}
