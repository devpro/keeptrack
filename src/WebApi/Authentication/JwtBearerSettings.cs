using Keeptrack.Common.Hosting.Authentication;

namespace Keeptrack.WebApi.Authentication;

/// <summary>
/// Either <see cref="Authority"/>, an issuer publishing its keys (Firebase), or <see cref="SigningKey"/>, the shared key of local authentication (see docs/authentication.md).
/// </summary>
public class JwtBearerSettings
{
    public string? Authority { get; set; }

    public string? SigningKey { get; set; }

    public required TokenValidationSettings TokenValidation { get; set; }

    /// <summary>
    /// Both set or neither is refused rather than resolved by precedence, since a silently ignored setting is a token validated against the wrong issuer.
    /// </summary>
    public void ApplyTo(JwtBearerOptions options)
    {
        var hasAuthority = !string.IsNullOrEmpty(Authority);
        var hasSigningKey = !string.IsNullOrEmpty(SigningKey);
        if (hasAuthority == hasSigningKey)
        {
            throw new InvalidOperationException("Exactly one of Authentication:JwtBearer:Authority and Authentication:JwtBearer:SigningKey must be set.");
        }

        // Claim names ("sub", "email", "role") must stay as issued.
        // The inbound claim mapping would rename short names like "role" to legacy ClaimTypes URIs, and RequireClaim("role", ...) would never match.
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = TokenValidation.Issuer,
            ValidateAudience = true,
            ValidAudience = TokenValidation.Audience,
            ValidateLifetime = true
        };
        if (hasAuthority)
        {
            options.Authority = Authority;
        }
        else
        {
            options.TokenValidationParameters.ValidateIssuerSigningKey = true;
            options.TokenValidationParameters.IssuerSigningKey = LocalSigningKey.Decode(SigningKey!);
        }
    }
}
