using System.Net;
using System.Net.Http.Headers;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Attaches IGDB's two required headers, <c>Client-ID</c> and the Twitch app bearer token, to every IGDB request, and recovers once from a rejected token.
/// <para>
/// A handler rather than per-call code, so <see cref="IgdbClient"/> stays a plain typed client and the token lifecycle lives in one place.
/// It has nothing to do with the application's own Firebase authentication.
/// </para>
/// <para>
/// On a 401 the cached token is dropped and the request sent once more with a fresh one, since a Twitch token can be revoked or expire early.
/// One retry only, since a second 401 means wrong credentials, which retrying cannot fix.
/// </para>
/// </summary>
public class IgdbAuthenticationHandler(IIgdbTokenProvider tokenProvider) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await tokenProvider.GetTokenAsync(cancellationToken);
        if (token is null) return Unauthorized(request);

        // Buffered first, since a sent HttpRequestMessage cannot be resent and its content is disposed after sending.
        // An IGDB body is a short Apicalypse string already in memory, so this costs nothing.
        var body = request.Content is null ? null : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var contentType = request.Content?.Headers.ContentType;

        Authorize(request, token);
        var response = await base.SendAsync(request, cancellationToken);
        if (response.StatusCode != HttpStatusCode.Unauthorized) return response;

        response.Dispose();
        tokenProvider.Invalidate();

        var refreshed = await tokenProvider.GetTokenAsync(cancellationToken);
        if (refreshed is null) return Unauthorized(request);

        var retry = CloneRequest(request, body, contentType);
        Authorize(retry, refreshed);
        return await base.SendAsync(retry, cancellationToken);
    }

    private void Authorize(HttpRequestMessage request, string token)
    {
        request.Headers.Remove("Client-ID");
        request.Headers.Add("Client-ID", tokenProvider.ClientId);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// A 401 built locally when there is no token to send (IGDB not configured, or Twitch refusing one).
    /// The client checks its configuration first, so this is exceptional, and a response rather than a throw looks like IGDB refusing, which callers handle.
    /// </summary>
    private static HttpResponseMessage Unauthorized(HttpRequestMessage request) =>
        new(HttpStatusCode.Unauthorized) { RequestMessage = request };

    private static HttpRequestMessage CloneRequest(HttpRequestMessage request, byte[]? body, MediaTypeHeaderValue? contentType)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
            Content = body is null ? null : new ByteArrayContent(body)
        };

        if (clone.Content is not null) clone.Content.Headers.ContentType = contentType;

        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        foreach (var option in request.Options)
        {
            clone.Options.TryAdd(option.Key, option.Value);
        }

        return clone;
    }
}
