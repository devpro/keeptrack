using Keeptrack.Testing.Shared.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The same host validating local tokens whatever the run's mode, so a Firebase run still proves the local path (see docs/authentication.md).
/// <para>
/// Added as a second configuration source, as <see cref="RawgDefaultVideoGameWebAppFactory"/> does, rather than passed to the base constructor:
/// a local run already carries the same keys there, and <see cref="Microsoft.Extensions.Configuration.Memory.MemoryConfigurationProvider"/> throws on a duplicate key within one source.
/// </para>
/// </summary>
public sealed class LocalAuthenticationWebAppFactory() : KestrelWebAppFactory<Program>([])
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(TestAuthentication.LocalWebApiConfiguration()));
    }
}
