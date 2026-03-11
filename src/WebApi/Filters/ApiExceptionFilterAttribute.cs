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
public sealed class ApiExceptionFilterAttribute : ExceptionFilterAttribute
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

        context.Result = new JsonResult(new { error = message });
        context.HttpContext.Response.StatusCode = statusCode;

        base.OnException(context);
    }
}
