using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Keeptrack.WebApi.Filters;

/// <summary>
/// An exception filter that intercepts unhandled exceptions thrown during action execution
/// and converts them into appropriate HTTP error responses with JSON bodies.
/// <para>
/// Argument exceptions (invalid input) are mapped to 400 Bad Request.
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
            _ => (context.Exception.Message, StatusCodes.Status500InternalServerError)
        };

        // logged here (not just left to be visible client-side) so a 500 - especially one caused by a
        // failing external provider call (TMDB/RAWG/Open Library/Discogs) - leaves a server-side trail to
        // diagnose after the fact, instead of only ever being visible as an opaque error in the browser.
        logger.LogError(context.Exception, "Unhandled exception in {Path}: {Message}", context.HttpContext.Request.Path, message);

        context.Result = new JsonResult(new { error = message });
        context.HttpContext.Response.StatusCode = statusCode;

        base.OnException(context);
    }
}
