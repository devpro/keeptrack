using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.WebApi.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Filters;

[Trait("Category", "UnitTests")]
public class ApiExceptionFilterAttributeTest
{
    private readonly ApiExceptionFilterAttribute _filter = new(NullLogger<ApiExceptionFilterAttribute>.Instance);

    private static ExceptionContext CreateContext(Exception exception)
    {
        var httpContext = new DefaultHttpContext();
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
        return new ExceptionContext(actionContext, new List<IFilterMetadata>()) { Exception = exception };
    }

    [Fact]
    public void OnException_MapsArgumentExceptionTo400()
    {
        var context = CreateContext(new ArgumentException("bad input"));

        _filter.OnException(context);

        context.HttpContext.Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
    }

    [Fact]
    public void OnException_MapsArgumentNullExceptionTo400()
    {
        var context = CreateContext(new ArgumentNullException("param"));

        _filter.OnException(context);

        context.HttpContext.Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
    }

    /// <summary>
    /// Everything else, including an exception surfacing from a failed external provider call (TMDB/RAWG/Open
    /// Library/Discogs) once the HTTP resilience handler's retries are exhausted, maps to 500 - the request
    /// still fails cleanly with a JSON body instead of an unhandled exception taking the process down.
    /// </summary>
    [Fact]
    public void OnException_MapsAnyOtherExceptionTo500()
    {
        var context = CreateContext(new InvalidOperationException("external provider call failed"));

        _filter.OnException(context);

        context.HttpContext.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
    }

    [Fact]
    public void OnException_SetsAJsonErrorBodyRatherThanLeakingTheRawException()
    {
        var context = CreateContext(new InvalidOperationException("boom"));

        _filter.OnException(context);

        var result = context.Result.Should().BeOfType<JsonResult>().Subject;
        result.Value.Should().BeEquivalentTo(new { error = "boom" });
    }
}
