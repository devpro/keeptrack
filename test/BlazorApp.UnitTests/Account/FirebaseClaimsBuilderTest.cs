using System.Collections.Generic;
using System.Security.Claims;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Account;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Account;

[Trait("Category", "UnitTests")]
public class FirebaseClaimsBuilderTest
{
    private const string Uid = "firebase-uid-123";

    [Fact]
    public void Build_StampsTheUidAsTheNameIdentifier()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object>());

        claims.Should().ContainSingle(c => c.Type == ClaimTypes.NameIdentifier && c.Value == Uid);
    }

    [Fact]
    public void Build_FallsBackToTheUid_WhenTheTokenCarriesNoName()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object>());

        claims.Should().ContainSingle(c => c.Type == ClaimTypes.Name && c.Value == Uid);
    }

    [Fact]
    public void Build_UsesTheTokensOwnName_WhenPresent()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object> { ["name"] = "Ada Lovelace" });

        claims.Should().ContainSingle(c => c.Type == ClaimTypes.Name && c.Value == "Ada Lovelace");
    }

    [Fact]
    public void Build_FallsBackToAnEmptyEmail_WhenTheTokenCarriesNone()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object>());

        claims.Should().ContainSingle(c => c.Type == ClaimTypes.Email && c.Value == "");
    }

    [Fact]
    public void Build_UsesTheTokensOwnEmail_WhenPresent()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object> { ["email"] = "ada@example.com" });

        claims.Should().ContainSingle(c => c.Type == ClaimTypes.Email && c.Value == "ada@example.com");
    }

    /// <summary>
    /// The security-relevant path: a token with no "role" custom claim must add no "role" claim at all,
    /// never a default/empty one, since Blazor's AdminOnly/MemberOnly policies key on the claim's mere
    /// presence (see AGENTS.md's "Free preview tier" section, an account with no role claim gets the free
    /// tier).
    /// </summary>
    [Fact]
    public void Build_AddsNoRoleClaim_WhenTheTokenCarriesNone()
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object>());

        claims.Should().NotContain(c => c.Type == "role");
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("member")]
    public void Build_CopiesTheRoleCustomClaimThrough(string role)
    {
        var claims = FirebaseClaimsBuilder.Build(Uid, new Dictionary<string, object> { ["role"] = role });

        claims.Should().ContainSingle(c => c.Type == "role" && c.Value == role);
    }
}
