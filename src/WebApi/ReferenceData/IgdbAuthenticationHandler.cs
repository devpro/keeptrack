using System.Net;
using System.Net.Http.Headers;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Attaches IGDB's two required headers - <c>Client-ID</c> and the Twitch app bearer token - to every outgoing
/// IGDB request, and recovers once from a rejected token.
/// <para>
/// A handler rather than something <see cref="IgdbClient"/> does per call, so the client stays a plain typed
/// client like every other provider's and the token's lifecycle lives in exactly one place. Nothing here
/// touches the application's own Firebase authentication.
/// </para>
/// <para>
/// On a 401 the cached token is dropped and the request is sent once more with a fresh one: a Twitch app token
/// can be revoked or expire early, and without this every subsequent call would keep failing against a token
/// the provider already refused. Exactly one retry - a second 401 means the credentials themselves are wrong,
/// which retrying cannot fix.
/// </para>
/// </summary>
public class IgdbAuthenticationHandler(IIgdbTokenProvider tokenProvider) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await tokenProvider.GetTokenAsync(cancellationToken);
        if (token is null) return Unauthorized(request);

        // buffered up front because the retry below needs a second message object (a sent HttpRequestMessage
        // cannot be resent) and the handler disposes the original's content once it has been sent. An IGDB body
        // is a short APIcalypse string that is already in memory, so this costs nothing.
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
    /// A 401 synthesized locally, for the two cases where there is no token to send at all (IGDB not
    /// configured, or Twitch refusing to issue one). The client checks its own configuration first, so this is
    /// the genuinely exceptional path - returning a response rather than throwing keeps it indistinguishable
    /// from IGDB itself refusing, which the callers already handle.
    /// </summary>
    private static HttpResponseMessage Unauthorized(HttpRequestMessage request) =>
        new(HttpStatusCode.Unauthorized) { RequestMessage = request };

    /// <summary>
    /// Copies method, uri, version, headers and the buffered body onto a fresh message.
    /// </summary>
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
