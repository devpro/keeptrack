using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace Keeptrack.WebApi.Filters;

/// <summary>
/// Logs every unhandled exception of an action and converts it into an HTTP error with a JSON body.
/// <para>
/// An argument exception (invalid input) becomes 400 Bad Request, a failed provider call 502 Bad Gateway, and anything else 500 Internal Server Error.
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
            // an upstream failure is not a defect here, so 502 says who failed where a 500 would read as a bug
            var ex when UpstreamFailure.Is(ex) =>
                (DescribeUpstreamFailure(ex), StatusCodes.Status502BadGateway),
            _ => (context.Exception.Message, StatusCodes.Status500InternalServerError)
        };

        // Logged here so a failed request, notably a failing provider call, leaves a server-side trail rather than only an error in the browser.
        // An upstream failure logs as a warning: worth a trail, but not this application erroring.
        var level = statusCode == StatusCodes.Status502BadGateway ? LogLevel.Warning : LogLevel.Error;
        logger.Log(level, context.Exception, "Unhandled exception in {Path}: {Message}", context.HttpContext.Request.Path, message);

        context.Result = new JsonResult(new { error = message });
        context.HttpContext.Response.StatusCode = statusCode;

        base.OnException(context);
    }

    /// <summary>
    /// Says what the provider actually did, in place of the raw framework message.
    /// <para>
    /// The default <see cref="HttpRequestException"/> text describes an exchange the reader cannot see,
    /// and once wrapped in this API's 502, the admin would only read "502 (Bad Gateway)", the provider's own status lost.
    /// A Google Books search outage, every <c>volumes?q=</c> answering 503, would then read as a bug here.
    /// The cases below are those that change what an operator does next: wait, retry, or switch provider.
    /// </para>
    /// The caller logs the original exception in full.
    /// </summary>
    private static string DescribeUpstreamFailure(Exception exception) => exception switch
    {
        // the provider answered, and with what, the most useful fact
        HttpRequestException { StatusCode: { } status } =>
            $"The external provider returned {(int)status} ({status}).",
        // no response at all: DNS, TLS, connection refused
        HttpRequestException => "The external provider could not be reached.",
        TimeoutRejectedException => "The external provider did not respond in time.",
        // the circuit is open, so this call was never attempted, which explains an instant failure unlike the slow ones that caused it
        BrokenCircuitException => "The external provider is failing repeatedly, so calls to it are paused for a short while.",
        _ => exception.Message
    };
}
