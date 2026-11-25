using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>The framework services a whole page asks for: a signed-in member, a fixed address and a browser answering nothing.</summary>
internal static class PageServices
{
    public static IServiceCollection AddPageServices(this IServiceCollection services) => services
        .AddAuthorizationCore(options => options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin")))
        .AddCascadingAuthenticationState()
        .AddSingleton<AuthenticationStateProvider, MemberState>()
        .AddSingleton<NavigationManager, FixedNavigation>()
        .AddSingleton<IJSRuntime, SilentBrowser>();

    private sealed class MemberState : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity([], "test"))));
    }

    private sealed class FixedNavigation : NavigationManager
    {
        public FixedNavigation() => Initialize("https://app.example/", "https://app.example/");
    }

    private sealed class SilentBrowser : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) => ValueTask.FromResult<TValue>(default!);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, System.Threading.CancellationToken cancellationToken, object?[]? args) =>
            ValueTask.FromResult<TValue>(default!);
    }
}
