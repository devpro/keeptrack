using System;
using System.Collections.Generic;
using System.Net.Http;
using AwesomeAssertions;
using Keeptrack.WebApi.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using Polly.CircuitBreaker;
using Polly.Timeout;
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
    /// The three ways a failed external provider call (TMDB/RAWG/Open Library/Discogs) surfaces out of the
    /// HTTP resilience pipeline - the total-request timeout expiring, the circuit breaker being open, and a
    /// non-success response after the retries are exhausted - all map to 502, never 500: the provider failed,
    /// this API didn't. A caller (and a CI test) can then tell an upstream outage from a defect here.
    /// </summary>
    [Theory]
    [MemberData(nameof(UpstreamProviderFailures))]
    public void OnException_MapsAFailedProviderCallTo502(Exception exception)
    {
        var context = CreateContext(exception);

        _filter.OnException(context);

        context.HttpContext.Response.StatusCode.Should().Be(StatusCodes.Status502BadGateway);
    }

    public static TheoryData<Exception> UpstreamProviderFailures() =>
    [
        new TimeoutRejectedException("provider took longer than the total request timeout"),
        new BrokenCircuitException("the circuit for this provider is open"),
        new HttpRequestException("Response status code does not indicate success: 503 (Service Unavailable).")
    ];

    /// <summary>
    /// Everything else maps to 500 - the request still fails cleanly with a JSON body instead of an unhandled
    /// exception taking the process down.
    /// </summary>
    [Fact]
    public void OnException_MapsAnyOtherExceptionTo500()
    {
        var context = CreateContext(new InvalidOperationException("something went wrong"));

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
