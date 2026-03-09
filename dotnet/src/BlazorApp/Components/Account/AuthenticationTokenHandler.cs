using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;

namespace KeepTrack.BlazorApp.Components.Account;

public class AuthenticationTokenHandler(IHttpContextAccessor httpContextAccessor)
    : DelegatingHandler
{
    private const string AuthorizationScheme = "Bearer";

    public const string FirebaseTokenName = "firebase_token";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = httpContextAccessor.HttpContext ?? throw new Exception("HttpContext not available");

        var token = await httpContext.GetTokenAsync(FirebaseTokenName);
        if (token is null) throw new TokenExpiredException();

        request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizationScheme, token);

        return await base.SendAsync(request, cancellationToken);
    }
}
