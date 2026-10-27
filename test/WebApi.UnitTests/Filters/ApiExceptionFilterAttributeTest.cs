using System;
using System.Collections.Generic;
using System.Net;
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
    /// The three ways a failed provider call surfaces out of the HTTP resilience pipeline all map to 502, never 500, since the provider failed, not this API.
    /// They are the total-request timeout expiring, the circuit breaker being open, and a non-success response after the retries are exhausted.
    /// A caller, and a CI test, can then tell an upstream outage from a defect here.
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
    /// Everything else maps to 500, so the request still fails cleanly with a JSON body instead of an unhandled exception taking the process down.
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

    private static string ErrorMessage(ExceptionContext context) =>
        context.Result.Should().BeOfType<JsonResult>().Subject.Value!.GetType().GetProperty("error")!
            .GetValue(context.Result.As<JsonResult>().Value)!.ToString()!;

    /// <summary>
    /// The provider's own status is the most useful fact about an upstream failure.
    /// Without it, the admin sees only this API's 502 through the Blazor client's EnsureSuccessStatusCode,
    /// and a Google Books search outage (volumes?q= answering 503) reads as a Keeptrack defect.
    /// </summary>
    [Fact]
    public void OnException_ReportsTheProvidersOwnStatus_WhenTheProviderAnswered()
    {
        var context = CreateContext(new HttpRequestException("Response status code does not indicate success: 503 (Service Unavailable).",
            null, HttpStatusCode.ServiceUnavailable));

        _filter.OnException(context);

        ErrorMessage(context).Should().Be("The external provider returned 503 (ServiceUnavailable).");
    }

    /// <summary>
    /// A provider that never answered (DNS, TLS, connection refused) carries no status, and saying so is more honest than naming a status nobody sent.
    /// </summary>
    [Fact]
    public void OnException_ReportsThatTheProviderWasUnreachable_WhenThereWasNoResponseAtAll()
    {
        var context = CreateContext(new HttpRequestException("No such host is known."));

        _filter.OnException(context);

        ErrorMessage(context).Should().Be("The external provider could not be reached.");
    }

    [Fact]
    public void OnException_ReportsATimeoutAsSuch()
    {
        var context = CreateContext(new TimeoutRejectedException("provider took longer than the total request timeout"));

        _filter.OnException(context);

        ErrorMessage(context).Should().Be("The external provider did not respond in time.");
    }

    /// <summary>
    /// An open circuit means the call was never attempted, worth saying, since it explains an instant failure that looks nothing like the slow one that caused it.
    /// </summary>
    [Fact]
    public void OnException_ExplainsAnOpenCircuit()
    {
        var context = CreateContext(new BrokenCircuitException("the circuit for this provider is open"));

        _filter.OnException(context);

        ErrorMessage(context).Should().Contain("failing repeatedly");
    }

    /// <summary>
    /// The framework's wording describes an exchange the reader can't see, so it is never shown to a user, and the full exception goes to the log.
    /// </summary>
    [Theory]
    [MemberData(nameof(UpstreamProviderFailures))]
    public void OnException_NeverEchoesTheRawFrameworkMessage_ForAnUpstreamFailure(Exception exception)
    {
        var context = CreateContext(exception);

        _filter.OnException(context);

        ErrorMessage(context).Should().NotBe(exception.Message);
    }
}
