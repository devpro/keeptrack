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

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

public class KestrelWebAppFactory<TEntryPoint> : WebApplicationFactory<TEntryPoint>
    where TEntryPoint : class
{
    private readonly string? _webapiUrl;

    private int _serverPort;

    public KestrelWebAppFactory()
    {
        _webapiUrl = Environment.GetEnvironmentVariable("KESTREL_WEBAPP_URL");
        if (string.IsNullOrEmpty(_webapiUrl))
        {
            UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // the periodic reference sync fires real TMDB calls against whatever reference data the test
        // Mongo instance happens to hold - undesirable noise/flakiness in a test run, not a regression to
        // chase down; the app's own default (Features:IsReferenceSyncEnabled=true in appsettings.json) is
        // unaffected, this only overrides the test host's configuration. ConfigureAppConfiguration (rather
        // than UseSetting, which loads before appsettings.json and so gets overridden by it) is added last
        // and wins.
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
        [
            new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false")
        ]));
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
