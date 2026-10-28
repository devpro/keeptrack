using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Keeptrack.Common.Hosting.Authentication;

/// <summary>
/// Mints the API bearer token of local authentication, carrying the claims WebApi reads from any issuer (see docs/authentication.md).
/// Shared by BlazorApp's sign-in and the test harness, so a test token is exactly what a signed-in user holds.
/// </summary>
public sealed class LocalTokenIssuer
{
    private readonly LocalTokenSettings _settings;

    private readonly SigningCredentials _signingCredentials;

    /// <remarks>Decodes the key here, so a bad key fails when the issuer is built at startup rather than at the first sign-in.</remarks>
    public LocalTokenIssuer(LocalTokenSettings settings)
    {
        _settings = settings;
        _signingCredentials = new SigningCredentials(LocalSigningKey.Decode(settings.SigningKey), SecurityAlgorithms.HmacSha256);
    }

    /// <summary>
    /// The subject is the normalized email, so signing in again with the same address reaches the same data.
    /// A null role adds no claim, which is the free preview tier.
    /// </summary>
    public static Dictionary<string, object> ClaimsFor(string email, string? role)
    {
        var normalizedEmail = email.Trim().ToLowerInvariant();
        var claims = new Dictionary<string, object>
        {
            ["sub"] = normalizedEmail,
            ["email"] = normalizedEmail,
            ["name"] = normalizedEmail
        };
        if (role is not null)
        {
            claims["role"] = role;
        }

        return claims;
    }

    public string Issue(string email, string? role, DateTimeOffset issuedAt, TimeSpan lifetime) =>
        Issue(ClaimsFor(email, role), issuedAt, lifetime);

    public string Issue(IDictionary<string, object> claims, DateTimeOffset issuedAt, TimeSpan lifetime)
    {
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _settings.Issuer,
            Audience = _settings.Audience,
            Claims = claims,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = issuedAt.Add(lifetime).UtcDateTime,
            SigningCredentials = _signingCredentials
        });
    }
}
