using System.Security.Claims;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Builds the cookie principal's claims from a verified Firebase token's own claims.
/// </summary>
/// <remarks>
/// A pure function, like <see cref="ReturnUrlResolver"/>, so the "role" claim copy is tested without a real Firebase token or HTTP pipeline.
/// It is the one place a Firebase custom claim (the "role" claim, set through the Firebase Admin SDK) crosses into Blazor's cookie principal,
/// which <c>AuthorizeView</c> and policy checks run against.
/// The bearer token WebApi validates carries the same claim on its own path, and <c>AddJwtBearer</c>'s <c>MapInboundClaims = false</c> has no bearing on this copy.
/// The two are checked independently, or the UI can show the admin nav link while the same user's API calls answer 403.
/// </remarks>
public static class FirebaseClaimsBuilder
{
    /// <param name="uid">The verified token's Firebase uid, stamped as <see cref="ClaimTypes.NameIdentifier"/>.</param>
    /// <param name="firebaseClaims">The verified token's own claims (<c>FirebaseToken.Claims</c>).</param>
    public static List<Claim> Build(string uid, IReadOnlyDictionary<string, object> firebaseClaims)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, uid),
            new(ClaimTypes.Name, firebaseClaims.TryGetValue("name", out var name) ? name.ToString()! : uid),
            new(ClaimTypes.Email, firebaseClaims.TryGetValue("email", out var email) ? email.ToString()! : "")
        };

        if (firebaseClaims.TryGetValue("role", out var role))
        {
            claims.Add(new Claim("role", role.ToString()!));
        }

        return claims;
    }
}
