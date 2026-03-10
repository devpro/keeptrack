using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Keeptrack.WebApi.Filters;

/// <summary>
/// Exception filter to make sure the
/// </summary>
public sealed class CustomExceptionFilterAttribute : ExceptionFilterAttribute
{
    /// <summary>
    /// Create a new instance of <see cref="CustomExceptionFilterAttribute"/>.
    /// </summary>
    public CustomExceptionFilterAttribute()
    {
    }

    /// <summary>
    /// Review when an exception is raised.
    /// </summary>
    /// <param name="context"></param>
    public override void OnException(ExceptionContext context)
    {
        switch (context.Exception)
        {
            case ArgumentNullException argumentNullException:
                context.Result = new JsonResult(argumentNullException.Message);
                context.HttpContext.Response.StatusCode = 400;
                break;
            case ArgumentException argumentException:
                context.Result = new JsonResult(argumentException.Message);
                context.HttpContext.Response.StatusCode = 400;
                break;
            default:
                context.Result = new JsonResult(context.Exception.Message);
                context.HttpContext.Response.StatusCode = 500;
                break;
        }
        base.OnException(context);
    }
}
