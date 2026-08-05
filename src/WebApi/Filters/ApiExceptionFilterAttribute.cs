using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace Keeptrack.WebApi.Filters;

/// <summary>
/// An exception filter that intercepts unhandled exceptions thrown during action execution
/// and converts them into appropriate HTTP error responses with JSON bodies.
/// <para>
/// Argument exceptions (invalid input) are mapped to 400 Bad Request.
/// A failed call to an external reference provider is mapped to 502 Bad Gateway.
/// All other exceptions are mapped to 500 Internal Server Error.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class ApiExceptionFilterAttribute(ILogger<ApiExceptionFilterAttribute> logger) : ExceptionFilterAttribute
{
    /// <inheritdoc />
    public override void OnException(ExceptionContext context)
    {
        var (message, statusCode) = context.Exception switch
        {
            ArgumentNullException ex => (ex.Message, StatusCodes.Status400BadRequest),
            ArgumentException ex => (ex.Message, StatusCodes.Status400BadRequest),
            // an external provider that timed out, exhausted its retries or tripped its circuit breaker is an
            // upstream failure, not a defect in this API - reporting it as 500 makes a provider outage
            // indistinguishable from a bug here, which is exactly how a degraded Open Library (real, measured:
            // 52s, then 503/504 past AddBookProviderResilienceHandler's 40s total budget) once read as a broken
            // endpoint. 502 says who failed. The only outbound HTTP an action makes is to those providers.
            TimeoutRejectedException or BrokenCircuitException or HttpRequestException =>
                (DescribeUpstreamFailure(context.Exception), StatusCodes.Status502BadGateway),
            _ => (context.Exception.Message, StatusCodes.Status500InternalServerError)
        };

        // logged here (not just left to be visible client-side) so a failed request - especially one caused by
        // a failing external provider call (TMDB/RAWG/Open Library/Discogs) - leaves a server-side trail to
        // diagnose after the fact, instead of only ever being visible as an opaque error in the browser.
        // An upstream failure logs as a warning: it is worth a trail, but it is not this application erroring.
        var level = statusCode == StatusCodes.Status502BadGateway ? LogLevel.Warning : LogLevel.Error;
        logger.Log(level, context.Exception, "Unhandled exception in {Path}: {Message}", context.HttpContext.Request.Path, message);

        context.Result = new JsonResult(new { error = message });
        context.HttpContext.Response.StatusCode = statusCode;

        base.OnException(context);
    }

    /// <summary>
    /// Says what the provider actually did, in place of the raw framework message.
    /// <para>
    /// The default <see cref="HttpRequestException"/> text ("Response status code does not indicate success:
    /// 503 (Service Unavailable).") describes an exchange the reader can't see, and once it has been wrapped
    /// in this API's own 502 and re-thrown by the Blazor client's <c>EnsureSuccessStatusCode</c>, what
    /// actually reaches the admin is "...: 502 (Bad Gateway)" - our gateway status, with the provider's real
    /// one lost. That is how a total Google Books search outage (confirmed: every <c>volumes?q=</c> query
    /// answering 503 while <c>volumes/{id}</c> answered 200) read as a bug in Keeptrack. The distinctions
    /// below are the ones that change what an operator should do next: wait, retry, or switch provider.
    /// </para>
    /// The original exception is still logged in full by the caller, so nothing is lost by not echoing it.
    /// </summary>
    private static string DescribeUpstreamFailure(Exception exception) => exception switch
    {
        // the provider answered, and with what - the single most useful fact, and the one previously dropped
        HttpRequestException { StatusCode: { } status } =>
            $"The external provider returned {(int)status} ({status}).",
        // no response at all: DNS, TLS, connection refused
        HttpRequestException => "The external provider could not be reached.",
        TimeoutRejectedException => "The external provider did not respond in time.",
        // Polly opened the circuit, so this call was never even attempted - worth saying, since it explains
        // an instant failure that looks nothing like the slow one that caused it
        BrokenCircuitException => "The external provider is failing repeatedly, so calls to it are paused for a short while.",
        _ => exception.Message
    };
}
