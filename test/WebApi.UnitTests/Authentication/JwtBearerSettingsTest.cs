using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.Hosting.Authentication;
using Keeptrack.WebApi.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Authentication;

/// <summary>
/// Signs with <see cref="LocalTokenIssuer"/>, as BlazorApp does in local mode, and validates with the parameters the WebApi applies,
/// so the two sides are proven to agree without a running host.
/// </summary>
[Trait("Category", "UnitTests")]
public class JwtBearerSettingsTest
{
    private const string Issuer = "keeptrack-unit-tests";

    private const string Audience = "keeptrack-unit-tests";

    private static readonly string s_signingKey = LocalSigningKey.Generate();

    [Fact]
    public async Task ApplyTo_WithASigningKey_AcceptsALocallyIssuedToken()
    {
        var options = Apply(LocalSettings(s_signingKey));
        var token = SignerFor(s_signingKey).Issue(" Ada@Example.com ", "admin", DateTimeOffset.UtcNow, TimeSpan.FromHours(8));

        var result = await ValidateAsync(options, token);

        result.IsValid.Should().BeTrue(result.Exception?.Message);
        result.ClaimsIdentity.FindFirst("sub")!.Value.Should().Be("ada@example.com");
        result.ClaimsIdentity.FindFirst("email")!.Value.Should().Be("ada@example.com");
        result.ClaimsIdentity.FindFirst("role")!.Value.Should().Be("admin");
    }

    /// <summary>
    /// A free preview account carries no role claim at all, never an empty one, since the policies key on the claim's presence.
    /// </summary>
    [Fact]
    public async Task ApplyTo_WithASigningKey_AcceptsATokenWithNoRole()
    {
        var options = Apply(LocalSettings(s_signingKey));
        var token = SignerFor(s_signingKey).Issue("ada@example.com", null, DateTimeOffset.UtcNow, TimeSpan.FromHours(8));

        var result = await ValidateAsync(options, token);

        result.IsValid.Should().BeTrue(result.Exception?.Message);
        result.ClaimsIdentity.Claims.Should().NotContain(c => c.Type == "role");
    }

    [Fact]
    public async Task ApplyTo_WithASigningKey_RejectsATokenSignedWithAnotherKey()
    {
        var options = Apply(LocalSettings(s_signingKey));
        var token = SignerFor(LocalSigningKey.Generate()).Issue("ada@example.com", "admin", DateTimeOffset.UtcNow, TimeSpan.FromHours(8));

        var result = await ValidateAsync(options, token);

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ApplyTo_WithASigningKey_RejectsAnExpiredToken()
    {
        var options = Apply(LocalSettings(s_signingKey));
        var token = SignerFor(s_signingKey).Issue("ada@example.com", "admin", DateTimeOffset.UtcNow.AddHours(-9), TimeSpan.FromHours(8));

        var result = await ValidateAsync(options, token);

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ApplyTo_WithASigningKey_RejectsAnotherIssuer()
    {
        var options = Apply(LocalSettings(s_signingKey));
        var token = new LocalTokenIssuer(new LocalTokenSettings { SigningKey = s_signingKey, Issuer = "someone-else", Audience = Audience })
            .Issue("ada@example.com", "admin", DateTimeOffset.UtcNow, TimeSpan.FromHours(8));

        var result = await ValidateAsync(options, token);

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void ApplyTo_WithAnAuthority_ValidatesAgainstItsPublishedKeys()
    {
        var options = Apply(new JwtBearerSettings
        {
            Authority = "https://securetoken.google.com/project",
            TokenValidation = new TokenValidationSettings { Issuer = "https://securetoken.google.com/project", Audience = "project" }
        });

        options.Authority.Should().Be("https://securetoken.google.com/project");
        options.TokenValidationParameters.IssuerSigningKey.Should().BeNull();
    }

    [Fact]
    public void ApplyTo_WithBothAnAuthorityAndASigningKey_Throws()
    {
        var settings = LocalSettings(s_signingKey);
        settings.Authority = "https://securetoken.google.com/project";

        var act = () => Apply(settings);

        act.Should().Throw<InvalidOperationException>().WithMessage("*Authority*SigningKey*");
    }

    [Fact]
    public void ApplyTo_WithNeitherAnAuthorityNorASigningKey_Throws()
    {
        var act = () => Apply(new JwtBearerSettings { TokenValidation = new TokenValidationSettings { Issuer = Issuer, Audience = Audience } });

        act.Should().Throw<InvalidOperationException>().WithMessage("*Authority*SigningKey*");
    }

    [Fact]
    public void ApplyTo_WithAShortSigningKey_Throws()
    {
        var act = () => Apply(LocalSettings(Convert.ToBase64String(new byte[16])));

        act.Should().Throw<InvalidOperationException>().WithMessage("*32 bytes*");
    }

    private static JwtBearerSettings LocalSettings(string signingKey) => new()
    {
        SigningKey = signingKey,
        TokenValidation = new TokenValidationSettings { Issuer = Issuer, Audience = Audience }
    };

    private static LocalTokenIssuer SignerFor(string signingKey) =>
        new(new LocalTokenSettings { SigningKey = signingKey, Issuer = Issuer, Audience = Audience });

    private static JwtBearerOptions Apply(JwtBearerSettings settings)
    {
        var options = new JwtBearerOptions();
        settings.ApplyTo(options);
        return options;
    }

    private static Task<Microsoft.IdentityModel.Tokens.TokenValidationResult> ValidateAsync(JwtBearerOptions options, string token) =>
        new JsonWebTokenHandler { MapInboundClaims = options.MapInboundClaims }.ValidateTokenAsync(token, options.TokenValidationParameters);
}
