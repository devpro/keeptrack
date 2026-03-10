using System;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
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
