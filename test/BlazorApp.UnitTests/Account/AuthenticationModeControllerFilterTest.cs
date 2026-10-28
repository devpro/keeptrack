using System.Collections.Generic;
using System.Reflection;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Account;
using Keeptrack.BlazorApp.Components.Account.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Account;

/// <summary>
/// Each mode's sign-in endpoints exist only in that mode, so the Firebase endpoints never run without a Firebase app,
/// and the password-less local sign-in never answers on a Firebase host.
/// </summary>
[Trait("Category", "UnitTests")]
public class AuthenticationModeControllerFilterTest
{
    [Fact]
    public void FirebaseMode_KeepsTheFirebaseControllerOnly()
    {
        var controllers = PopulateWith(AuthenticationMode.Firebase);

        controllers.Should().Contain(typeof(FirebaseAuthenticationController).GetTypeInfo());
        controllers.Should().NotContain(typeof(LocalAuthenticationController).GetTypeInfo());
    }

    [Fact]
    public void LocalMode_KeepsTheLocalControllerOnly()
    {
        var controllers = PopulateWith(AuthenticationMode.Local);

        controllers.Should().Contain(typeof(LocalAuthenticationController).GetTypeInfo());
        controllers.Should().NotContain(typeof(FirebaseAuthenticationController).GetTypeInfo());
    }

    [Fact]
    public void EitherMode_KeepsAControllerNotTiedToAMode()
    {
        PopulateWith(AuthenticationMode.Firebase).Should().Contain(typeof(UnrelatedController).GetTypeInfo());
        PopulateWith(AuthenticationMode.Local).Should().Contain(typeof(UnrelatedController).GetTypeInfo());
    }

    private static IList<TypeInfo> PopulateWith(AuthenticationMode mode)
    {
        var feature = new ControllerFeature();
        feature.Controllers.Add(typeof(FirebaseAuthenticationController).GetTypeInfo());
        feature.Controllers.Add(typeof(LocalAuthenticationController).GetTypeInfo());
        feature.Controllers.Add(typeof(UnrelatedController).GetTypeInfo());

        new AuthenticationModeControllerFilter(mode).PopulateFeature([], feature);

        return feature.Controllers;
    }

    private sealed class UnrelatedController : ControllerBase;
}
