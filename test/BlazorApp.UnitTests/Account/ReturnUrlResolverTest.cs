using System;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Account;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Account;

[Trait("Category", "UnitTests")]
public class ReturnUrlResolverTest
{
    private const string AppHost = "app.example:5207";

    // Stand-ins for the production predicate (IUrlHelper.IsLocalUrl). Tests state the predicate's answer
    // explicitly so each one targets the resolver's own branch logic, not IsLocalUrl's implementation.
    private static readonly Func<string, bool> s_treatAsLocal = _ => true;
    private static readonly Func<string, bool> s_treatAsNotLocal = _ => false;

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_ReturnsRoot_ForMissingReturnUrl(string? returnUrl)
    {
        ReturnUrlResolver.Resolve(returnUrl, AppHost, s_treatAsLocal).Should().Be("/");
    }

    [Fact]
    public void Resolve_PassesThroughAUrlThePredicateAcceptsAsLocal()
    {
        ReturnUrlResolver.Resolve("/movies?page=2", AppHost, s_treatAsLocal)
            .Should().Be("/movies?page=2");
    }

    [Fact]
    public void Resolve_ReducesSameHostAbsoluteUrl_ToPathAndQuery()
    {
        // The genuine callers pass this app's own absolute NavigationManager.Uri.
        ReturnUrlResolver.Resolve("https://app.example:5207/movies?page=2", AppHost, s_treatAsNotLocal)
            .Should().Be("/movies?page=2");
    }

    [Fact]
    public void Resolve_MatchesHostCaseInsensitively()
    {
        ReturnUrlResolver.Resolve("https://APP.EXAMPLE:5207/tv-shows", AppHost, s_treatAsNotLocal)
            .Should().Be("/tv-shows");
    }

    [Fact]
    public void Resolve_ReturnsRoot_ForADifferentHostAbsoluteUrl()
    {
        // The core open-redirect guard: never bounce a signed-in user off-site.
        ReturnUrlResolver.Resolve("https://evil.example/movies", AppHost, s_treatAsNotLocal)
            .Should().Be("/");
    }

    [Fact]
    public void Resolve_ReturnsRoot_WhenUserInfoSpoofsTheHost()
    {
        // The parsed authority is evil.example (the part before '@' is userinfo), not the app host.
        ReturnUrlResolver.Resolve("https://app.example:5207@evil.example/x", AppHost, s_treatAsNotLocal)
            .Should().Be("/");
    }

    [Theory]
    [InlineData("//evil.example/x")]
    [InlineData("/\\evil.example")]
    public void Resolve_ReturnsRoot_ForUrlsThePredicateRejects(string returnUrl)
    {
        // These are the dangerous shapes IUrlHelper.IsLocalUrl rejects (protocol-relative, backslash
        // authority). The resolver defers that judgment to the predicate and does not smuggle them through
        // the absolute-URL branch - neither parses as an absolute Uri - so they fall back to the app root.
        ReturnUrlResolver.Resolve(returnUrl, AppHost, s_treatAsNotLocal)
            .Should().Be("/");
    }
}
