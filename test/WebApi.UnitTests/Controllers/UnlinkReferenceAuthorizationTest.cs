using System;
using System.Linq;
using System.Reflection;
using AwesomeAssertions;
using Keeptrack.WebApi.Controllers;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Controllers;

/// <summary>
/// The "unlink-reference" action on each reference-linked controller deletes shared data (the reference
/// document itself), unlike the harmless/idempotent "refresh-reference" action next to it - it must
/// carry its own method-level <c>AdminOnly</c> policy on top of whatever the controller class itself
/// requires. A reflection guard here (same shape as <c>FreeTierTest.Controller_CarriesTheExpectedAuthorizationPolicy</c>,
/// just at the method level instead of the class level) means removing the attribute is a failing test,
/// not a silent privilege-escalation bug - the integration suite can't exercise a 403 here directly since
/// its one Firebase test user is an admin (see <c>FreeTierTest</c>'s own doc comment).
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
