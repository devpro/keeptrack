using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Account;
using Keeptrack.BlazorApp.Components.Account.Controllers;
using Keeptrack.Common.Hosting.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Account;

[Trait("Category", "UnitTests")]
public class LocalAuthenticationControllerTest
{
    private readonly RecordingAuthenticationService _authentication = new();

    [Fact]
    public async Task SignIn_WithAnEmailAndARole_SignsInWithAMatchingApiToken()
    {
        var result = await CreateController().SignIn(new LocalSignInRequest(" Ada@Example.com ", "admin", "/books"));

        result.Should().BeOfType<OkObjectResult>();
        var principal = _authentication.SignedInPrincipal!;
        principal.FindFirstValue(ClaimTypes.NameIdentifier).Should().Be("ada@example.com");
        principal.FindFirstValue(ClaimTypes.Email).Should().Be("ada@example.com");
        principal.FindFirstValue("role").Should().Be("admin");

        var token = _authentication.SignedInProperties!.GetTokenValue(AuthenticationTokenHandler.ApiTokenName);
        ReadPayload(token!).GetProperty("sub").GetString().Should().Be("ada@example.com");
    }

    [Fact]
    public async Task SignIn_ReturnsTheLocalReturnUrl()
    {
        var result = await CreateController().SignIn(new LocalSignInRequest("ada@example.com", null, "/books"));

        JsonSerializer.Serialize(((OkObjectResult)result).Value).Should().Be("""{"redirect":"/books"}""");
    }

    /// <summary>
    /// A free preview account carries no role claim at all, since the policies key on the claim's presence.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task SignIn_WithNoRole_SignsInAFreeAccount(string? role)
    {
        await CreateController().SignIn(new LocalSignInRequest("ada@example.com", role, null));

        _authentication.SignedInPrincipal!.FindFirst("role").Should().BeNull();
        ReadPayload(_authentication.SignedInProperties!.GetTokenValue(AuthenticationTokenHandler.ApiTokenName)!).TryGetProperty("role", out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(" ")]
    public async Task SignIn_WithNoEmail_Answers400(string? email)
    {
        var result = await CreateController().SignIn(new LocalSignInRequest(email, "admin", null));

        result.Should().BeOfType<BadRequestObjectResult>();
        _authentication.SignedInPrincipal.Should().BeNull();
    }

    [Fact]
    public async Task SignIn_WithAnUnknownRole_Answers400()
    {
        var result = await CreateController().SignIn(new LocalSignInRequest("ada@example.com", "owner", null));

        result.Should().BeOfType<BadRequestObjectResult>();
        _authentication.SignedInPrincipal.Should().BeNull();
    }

    private LocalAuthenticationController CreateController()
    {
        var services = new ServiceCollection()
            .AddSingleton<IAuthenticationService>(_authentication)
            .AddSingleton<IUrlHelperFactory, UrlHelperFactory>()
            .BuildServiceProvider();
        var httpContext = new DefaultHttpContext { RequestServices = services };
        httpContext.Request.Host = new HostString("localhost");

        var issuer = new LocalTokenIssuer(new LocalTokenSettings { SigningKey = LocalSigningKey.Generate(), Issuer = "tests", Audience = "tests" });
        var actionContext = new ActionContext(httpContext, new RouteData(), new ControllerActionDescriptor());
        return new LocalAuthenticationController(issuer) { ControllerContext = new ControllerContext(actionContext) };
    }

    private static JsonElement ReadPayload(string token)
    {
        var payload = token.Split('.')[1];
        var padded = payload.Replace('-', '+').Replace('_', '/').PadRight((payload.Length + 3) / 4 * 4, '=');
        return JsonDocument.Parse(System.Convert.FromBase64String(padded)).RootElement;
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public ClaimsPrincipal? SignedInPrincipal { get; private set; }

        public AuthenticationProperties? SignedInProperties { get; private set; }

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            SignedInPrincipal = principal;
            SignedInProperties = properties;
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }
}
