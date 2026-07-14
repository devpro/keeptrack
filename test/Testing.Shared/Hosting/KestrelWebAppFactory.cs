using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Keeptrack.Testing.Shared.Hosting;

/// <summary>
/// In-process (or already-running, via <paramref name="urlOverrideEnvironmentVariable"/>) Kestrel host for a
/// test suite. Shared by <c>WebApi.IntegrationTests</c> and <c>BlazorApp.E2eTests</c>, so the env-var override
/// name and any in-memory configuration overrides (e.g. disabling a background sync job that would otherwise
/// fire real outbound calls against shared test data) are constructor parameters rather than hardcoded, letting
/// each host (WebApi, BlazorApp) supply its own.
/// </summary>
public class KestrelWebAppFactory<TEntryPoint> : WebApplicationFactory<TEntryPoint>
    where TEntryPoint : class
{
    private readonly string? _webapiUrl;

    private readonly IReadOnlyList<KeyValuePair<string, string?>> _configOverrides;

    private int _serverPort;

    public KestrelWebAppFactory(string urlOverrideEnvironmentVariable, params KeyValuePair<string, string?>[] configOverrides)
    {
        _webapiUrl = Environment.GetEnvironmentVariable(urlOverrideEnvironmentVariable);
        _configOverrides = configOverrides;
        if (string.IsNullOrEmpty(_webapiUrl))
        {
            UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // ConfigureAppConfiguration (rather than UseSetting, which loads before appsettings.json and so gets
        // overridden by it) is added last and wins.
        if (_configOverrides.Count > 0)
        {
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(_configOverrides));
        }
        base.ConfigureWebHost(builder);
    }

    public string ServerAddress
    {
        get
        {
            if (!string.IsNullOrEmpty(_webapiUrl))
            {
                return _webapiUrl;
            }

            EnsureServerStarted();
            return $"http://127.0.0.1:{_serverPort}";

        }
    }

    private void EnsureServerStarted()
    {
        if (_serverPort != 0) return;

        // forces Kestrel binding
        StartServer();

        // extracts dynamic port
        var server = Services.GetRequiredService<IServer>();
        var addressesFeature = server.Features.Get<IServerAddressesFeature>();
        var address = addressesFeature?.Addresses.FirstOrDefault()
                      ?? throw new InvalidOperationException("No bound address found.");

        // parses port (address may be "http://[::]:51234")
        var uri = new Uri(address);
        _serverPort = uri.Port;
    }
}
