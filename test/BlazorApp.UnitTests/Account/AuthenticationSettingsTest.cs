using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Account;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Account;

[Trait("Category", "UnitTests")]
public class AuthenticationSettingsTest
{
    [Fact]
    public void ResolveMode_DefaultsToFirebase()
    {
        AuthenticationSettings.ResolveMode(Configuration(null), "Production").Should().Be(AuthenticationMode.Firebase);
    }

    [Theory]
    [InlineData("Local", "Development")]
    [InlineData("local", "Test")]
    public void ResolveMode_ReadsLocal_OutsideProduction(string mode, string environmentName)
    {
        AuthenticationSettings.ResolveMode(Configuration(mode), environmentName).Should().Be(AuthenticationMode.Local);
    }

    /// <summary>
    /// The local login form signs anyone in as anyone, admin included, so a production host must never serve it.
    /// </summary>
    [Fact]
    public void ResolveMode_RefusesLocal_InProduction()
    {
        var act = () => AuthenticationSettings.ResolveMode(Configuration("Local"), "Production");

        act.Should().Throw<InvalidOperationException>().WithMessage("*Production*");
    }

    [Fact]
    public void ResolveMode_RefusesAnUnknownMode()
    {
        var act = () => AuthenticationSettings.ResolveMode(Configuration("Keycloak"), "Development");

        act.Should().Throw<InvalidOperationException>().WithMessage("*Keycloak*");
    }

    private static IConfiguration Configuration(string? mode) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Authentication:Mode"] = mode })
            .Build();
}
