using System.Net;
using System.Text.Json.Serialization;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// A failed API call, carrying the message the API itself reported rather than a framework-generated one.
/// </summary>
/// <remarks>
/// <see cref="HttpResponseMessage.EnsureSuccessStatusCode"/> throws with only the status line ("Response
/// status code does not indicate success: 502 (Bad Gateway).") and discards the response body - so the
/// <c>{ error }</c> the API deliberately writes (see <c>ApiExceptionFilterAttribute</c>) never reached a
/// single user, and every upstream provider outage surfaced as an unexplained 502.
/// </remarks>
public sealed class ApiRequestException(string message, HttpStatusCode statusCode) : Exception(message)
{
    /// <summary>The status the API answered with - not the upstream provider's own, when there was one.</summary>
    public HttpStatusCode StatusCode { get; } = statusCode;

    /// <summary>
    /// True when the API reported that ITS upstream call failed rather than failing itself, which is the
    /// distinction that decides whether retrying the same thing is worth the user's time or whether they
    /// should reach for another provider. See <c>ApiExceptionFilterAttribute</c> for why that is a 502.
    /// </summary>
    public bool IsUpstreamProviderFailure => StatusCode == HttpStatusCode.BadGateway;
}

/// <summary>
/// Reads the API's own error payload off a failed response, so a caller can show what actually went wrong.
/// </summary>
public static class ApiResponseExtensions
{
    /// <summary>
    /// Drop-in replacement for <see cref="HttpResponseMessage.EnsureSuccessStatusCode"/> that preserves the
    /// API's reported message.
    /// </summary>
    public static async Task EnsureSuccessOrThrowAsync(this HttpResponseMessage response, CancellationToken cancellationToken = default)
    {
        if (response.IsSuccessStatusCode) return;

        throw new ApiRequestException(await ReadErrorMessageAsync(response, cancellationToken), response.StatusCode);
    }

    /// <summary>
    /// The success body, or an <see cref="ApiRequestException"/> carrying the API's own message. Use instead
    /// of <c>GetFromJsonAsync</c> wherever the failure is shown to a user.
    /// </summary>
    public static async Task<T?> ReadJsonOrThrowAsync<T>(this HttpResponseMessage response, CancellationToken cancellationToken = default)
    {
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<T>(cancellationToken);
    }

    /// <summary>
    /// Falls back to the status line for a response with no <c>{ error }</c> body at all - an error page from
    /// a proxy in front of the API, an empty 500, a non-JSON body. A failure while reading the explanation of
    /// a failure must never replace it with an exception of its own.
    /// </summary>
    private static async Task<string> ReadErrorMessageAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadFromJsonAsync<ApiErrorBody>(cancellationToken);
            if (!string.IsNullOrWhiteSpace(body?.Error)) return body.Error;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // not JSON, or not this shape - the status line below is still better than nothing
        }

        return $"The request failed ({(int)response.StatusCode} {response.ReasonPhrase}).";
    }

    private sealed class ApiErrorBody
    {
        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }
}
