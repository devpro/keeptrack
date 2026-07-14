namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Normalizes a caller-supplied return URL to a safe, same-origin local path, guarding against an
/// open-redirect: an attacker-crafted <c>?returnUrl=https://evil.example</c> must never send a
/// freshly-signed-in user off-site.
/// </summary>
public static class ReturnUrlResolver
{
    /// <summary>
    /// Relative local URLs (as judged by <paramref name="isLocalUrl"/>, which is
    /// <see cref="Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl"/> in production) pass through untouched;
    /// an absolute URL is accepted only when it targets <paramref name="appHost"/>, reduced to its
    /// path+query; anything else falls back to the app root. The genuine callers (RedirectToLogin, the
    /// token handler) pass this app's own absolute <c>NavigationManager.Uri</c>, which the same-host branch
    /// handles. The "is this a safe local URL" decision is deferred to <paramref name="isLocalUrl"/> rather
    /// than reimplemented, since the edge cases it guards (<c>//host</c>, <c>/\host</c>, control chars) are
    /// easy to get subtly wrong.
    /// </summary>
    public static string Resolve(string? returnUrl, string appHost, Func<string, bool> isLocalUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return "/";
        if (isLocalUrl(returnUrl)) return returnUrl;
        if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absolute)
            && string.Equals(absolute.Authority, appHost, StringComparison.OrdinalIgnoreCase))
        {
            return absolute.PathAndQuery;
        }

        return "/";
    }
}
