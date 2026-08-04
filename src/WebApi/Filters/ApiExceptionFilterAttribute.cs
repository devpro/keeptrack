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
                (context.Exception.Message, StatusCodes.Status502BadGateway),
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
}
