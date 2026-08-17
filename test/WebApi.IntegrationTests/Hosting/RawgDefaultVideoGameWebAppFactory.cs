using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The same host with the video game default provider forced to RAWG instead of IGDB, so a test can prove
/// the admin provider picker's default follows <c>ReferenceData:VideoGameProvider</c> rather than DI
/// registration order (IGDB always registers first regardless of this setting, see Program.cs).
/// <para>
/// Added as a second <see cref="IConfigurationBuilder"/> source rather than appended to the base
/// constructor's override array: that array already carries <c>ReferenceData:VideoGameProvider=igdb</c>, and
/// <see cref="MemoryConfigurationProvider"/> throws on a duplicate key within one <c>AddInMemoryCollection</c>
/// call. A source added later still wins on key conflict, which is the ordinary configuration precedence rule.
/// </para>
/// </summary>
public sealed class RawgDefaultVideoGameWebAppFactory() : KestrelWebAppFactory<Program>([])
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
        [
            new KeyValuePair<string, string?>("ReferenceData:VideoGameProvider", "rawg")
        ]));
    }
}
