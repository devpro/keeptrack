using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;

namespace Keeptrack.BlazorApp.Components.Account;

public class AuthenticationTokenHandler(
    IHttpContextAccessor httpContextAccessor)
    : DelegatingHandler
{
    private const string AuthorizationScheme = "Bearer";

    public const string FirebaseTokenName = "firebase_token";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = httpContextAccessor.HttpContext ?? throw new InvalidOperationException("HttpContext is not available");

        var token = await httpContext.GetTokenAsync(FirebaseTokenName);
        if (token is null) RedirectToLogin(httpContext);

        request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizationScheme, token);

        var response = await base.SendAsync(request, cancellationToken);

        // The auth cookie (8h, sliding) outlives the Firebase ID token it carries, which expires after about 1h.
        // Client-side refresh (onIdTokenChanged in FirebaseSessionRefresh, and the /auth/refresh endpoint) normally keeps the stored token current.
        // When it can't (a revoked token, or a session past the cookie's lifetime), a call comes back 401, and the user is sent to login rather than shown a raw 401.
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            response.Dispose();
            RedirectToLogin(httpContext);
        }

        return response;
    }

    [DoesNotReturn]
    private static void RedirectToLogin(HttpContext httpContext)
    {
        // The NavigationManager comes from the request's DI scope, not the constructor.
        // IHttpClientFactory builds this handler in its own scope, whose RemoteNavigationManager the renderer never initialized,
        // so .Uri and .NavigateTo throw "RemoteNavigationManager has not been initialized" during prerender.
        // The endpoint renderer initializes the request scope's NavigationManager before OnInitializedAsync, so it is safe here.
        var navigationManager = httpContext.RequestServices.GetRequiredService<NavigationManager>();
        var returnUrl = Uri.EscapeDataString(navigationManager.Uri);
        // forceLoad makes a full navigation to the login page, re-running the Firebase sign-in and re-issuing the cookie, where an in-circuit render would keep the dead session.
        // During static SSR it throws a NavigationException the framework turns into a redirect, and in an interactive circuit it navigates the browser directly.
        navigationManager.NavigateTo($"account/login?returnUrl={returnUrl}", forceLoad: true);
        throw new TokenExpiredException();
    }
}
