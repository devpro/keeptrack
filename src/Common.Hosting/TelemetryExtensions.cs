using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Keeptrack.Common.Hosting;

/// <summary>
/// OpenTelemetry of both applications, configured by the standard OTEL_* environment variables (service name, resource attributes, protocol).
/// </summary>
public static class TelemetryExtensions
{
    private static readonly PathString s_healthCheckPath = new("/healthz");

    public static IHostApplicationBuilder AddKeeptrackTelemetry(this IHostApplicationBuilder builder)
    {
        // Off without a collector, so a local run or a test host never retries exports to an endpoint nobody listens on.
        if (string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        {
            return builder;
        }

        builder.Services.AddOpenTelemetry()
            .WithTracing(tracing => tracing
                // The probes of every replica would otherwise outnumber the real requests.
                .AddAspNetCoreInstrumentation(options => options.Filter = context => !context.Request.Path.StartsWithSegments(s_healthCheckPath))
                .AddHttpClientInstrumentation()
                // The driver emits a span per command from its own ActivitySource, with no extra package.
                .AddSource("MongoDB.Driver"))
            .WithMetrics(metrics => metrics
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation())
            .WithLogging(_ => { }, options =>
            {
                options.IncludeFormattedMessage = true;
                options.IncludeScopes = true;
            })
            .UseOtlpExporter();
        return builder;
    }
}
