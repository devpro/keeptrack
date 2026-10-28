using System.Diagnostics;
using System.Linq;
using AwesomeAssertions;
using Keeptrack.Common.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Hosting;

[Trait("Category", "UnitTests")]
public class TelemetryExtensionsTest
{
    [Fact]
    public void AddKeeptrackTelemetry_RegistersNothing_WhenNoOtlpEndpointIsSet()
    {
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());

        builder.AddKeeptrackTelemetry();

        using var app = builder.Build();
        app.Services.GetService<TracerProvider>().Should().BeNull();
        app.Services.GetService<MeterProvider>().Should().BeNull();
        app.Services.GetServices<ILoggerProvider>().Should().NotContain(x => x is OpenTelemetryLoggerProvider);
    }

    [Fact]
    public void AddKeeptrackTelemetry_ExportsTracesMetricsAndLogs_WhenAnOtlpEndpointIsSet()
    {
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://localhost:4317";

        builder.AddKeeptrackTelemetry();

        using var app = builder.Build();
        app.Services.GetService<TracerProvider>().Should().NotBeNull();
        app.Services.GetService<MeterProvider>().Should().NotBeNull();
        app.Services.GetServices<ILoggerProvider>().Should().Contain(x => x is OpenTelemetryLoggerProvider);
        new[] { "Microsoft.AspNetCore", "System.Net.Http", "MongoDB.Driver" }
            .Where(name => !new ActivitySource(name).HasListeners())
            .Should().BeEmpty("incoming requests, provider calls and MongoDB commands are all traced");
    }
}
