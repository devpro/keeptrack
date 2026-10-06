namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Normalizes a caller-supplied return URL to a safe, same-origin local path, against an open redirect.
/// A crafted <c>?returnUrl=https://evil.example</c> must never send a freshly signed-in user off-site.
/// </summary>
public static class ReturnUrlResolver
{
    /// <summary>
    /// A relative local URL, as judged by <paramref name="isLocalUrl"/> (<see cref="Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl"/> in production), passes through untouched.
    /// An absolute URL is accepted only when it targets <paramref name="appHost"/>, reduced to its path and query, and anything else falls back to the app root.
    /// The genuine callers (RedirectToLogin, the token handler) pass this app's absolute <c>NavigationManager.Uri</c>, which the same-host branch handles.
    /// The local URL decision is left to <paramref name="isLocalUrl"/> rather than reimplemented, since its edge cases (<c>//host</c>, <c>/\host</c>, control characters) are easy to get subtly wrong.
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
