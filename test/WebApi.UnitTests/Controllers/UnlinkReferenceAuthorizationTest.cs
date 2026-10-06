using System;
using System.Linq;
using System.Reflection;
using AwesomeAssertions;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Controllers;

/// <summary>
/// The "unlink-reference" action on each reference-linked controller deletes shared data (the reference document), unlike the harmless "refresh-reference" beside it, so it carries its own method-level <c>AdminOnly</c> policy.
/// A reflection guard, like <c>FreeTierTest.Controller_CarriesTheExpectedAuthorizationPolicy</c> at the method level, makes removing the attribute a failing test rather than a silent privilege escalation.
/// The integration suite can't exercise the 403, its one Firebase test user being an admin (see <c>FreeTierTest</c>).
/// </summary>
[Trait("Category", "UnitTests")]
public class UnlinkReferenceAuthorizationTest
{
    [Theory]
    [InlineData(typeof(TvShowController))]
    [InlineData(typeof(MovieController))]
    [InlineData(typeof(BookController))]
    [InlineData(typeof(VideoGameController))]
    [InlineData(typeof(AlbumController))]
    public void UnlinkReference_CarriesTheAdminOnlyPolicy(Type controllerType)
    {
        var method = controllerType.GetMethod("UnlinkReference", BindingFlags.Public | BindingFlags.Instance)
                     ?? throw new InvalidOperationException($"{controllerType.Name} has no UnlinkReference method.");

        var attribute = method.GetCustomAttributes<AuthorizeAttribute>(inherit: false).Single();

        attribute.Policy.Should().Be("AdminOnly");
    }
}
