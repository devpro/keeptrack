using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Account;

public class AuthenticationTokenHandler(
    IHttpContextAccessor httpContextAccessor,
    NavigationManager navigationManager)
    : DelegatingHandler
{
    private const string AuthorizationScheme = "Bearer";

    public const string FirebaseTokenName = "firebase_token";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = httpContextAccessor.HttpContext ?? throw new InvalidOperationException("HttpContext is not available");

        var token = await httpContext.GetTokenAsync(FirebaseTokenName);
        if (token is null) RedirectToLogin();

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
            RedirectToLogin();
        }

        return response;
    }

    [DoesNotReturn]
    private void RedirectToLogin()
    {
        var returnUrl = Uri.EscapeDataString(navigationManager.Uri);
        // forceLoad so the browser does a full navigation to the login page (re-running the Firebase sign-in
        // flow and re-issuing the cookie) instead of an in-circuit render that would keep the dead session.
        // During static SSR this throws a NavigationException the framework turns into a redirect; during an
        // interactive circuit it triggers the browser navigation directly.
        navigationManager.NavigateTo($"account/login?returnUrl={returnUrl}", forceLoad: true);
        throw new TokenExpiredException();
    }
}
