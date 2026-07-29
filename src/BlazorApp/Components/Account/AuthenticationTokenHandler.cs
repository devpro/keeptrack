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

        // The auth cookie (8h, sliding) deliberately outlives the Firebase ID token it carries (Firebase
        // tokens expire after ~1h). Client-side refresh (Firebase's onIdTokenChanged wiring in
        // FirebaseSessionRefresh + the /auth/refresh endpoint) normally keeps the stored token current, so
        // this rarely fires - but when it can't (the token was revoked, or the session is past the cookie's
        // own lifetime) a call reaches the API with a stale token and comes back 401. Bounce to login rather
        // than surfacing a raw 401 to the page.
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
        // The NavigationManager is resolved from the request's own DI scope, NOT constructor-injected:
        // IHttpClientFactory builds this DelegatingHandler in a separate handler scope whose
        // RemoteNavigationManager the renderer never initialized, so its .Uri / .NavigateTo throw
        // "RemoteNavigationManager has not been initialized" during the SSR/prerender pass (the intermittent
        // red error a page refresh worked around). The request scope's NavigationManager is the one the
        // endpoint renderer already initialized before running OnInitializedAsync, so it is safe to use here.
        var navigationManager = httpContext.RequestServices.GetRequiredService<NavigationManager>();
        var returnUrl = Uri.EscapeDataString(navigationManager.Uri);
        // forceLoad so the browser does a full navigation to the login page (re-running the Firebase sign-in
        // flow and re-issuing the cookie) instead of an in-circuit render that would keep the dead session.
        // During static SSR this throws a NavigationException the framework turns into a redirect; during an
        // interactive circuit it triggers the browser navigation directly.
        navigationManager.NavigateTo($"account/login?returnUrl={returnUrl}", forceLoad: true);
        throw new TokenExpiredException();
    }
}
