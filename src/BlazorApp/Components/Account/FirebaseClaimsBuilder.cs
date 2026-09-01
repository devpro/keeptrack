using System.Security.Claims;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Builds the cookie principal's claims from a verified Firebase token's own claims.
/// </summary>
/// <remarks>
/// Extracted as a pure function, the same convention as <see cref="ReturnUrlResolver"/>, so the "role"
/// custom-claim copy can be tested without standing up a real Firebase token or HTTP pipeline.
/// This is the one place a Firebase custom claim (the admin "role" claim, set via the Firebase Admin SDK)
/// crosses into Blazor's own cookie principal, which is what <c>AuthorizeView</c>/policy checks run against
/// here (the bearer token WebApi validates separately carries the same claim, but on its own path).
/// A drift between the two was a real incident: it once let the Blazor UI show the admin nav link while the
/// same user's API call still 403'd, because <c>AddJwtBearer</c>'s <c>MapInboundClaims = false</c> setting
/// on the API side has no bearing on this cookie copy at all, so the two must be checked independently.
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
