using System.Collections.Generic;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Thin subclass over the shared <see cref="Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory{TEntryPoint}"/>,
/// preserving this project's exact pre-extraction behavior: the <c>KESTREL_WEBAPP_URL</c> override variable, and
/// disabling <see cref="Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService"/> so it doesn't fire real
/// TMDB calls against shared test data on every host start-up (see <see cref="Keeptrack.WebApi.AppConfiguration.IsReferenceSyncEnabled"/>).
/// <para>
/// Every fixture in this project routes through here, which is why the
/// <see cref="Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard"/> check lives in the constructor: it makes
/// "this suite never writes to the developer's own database" a property of the host itself rather than
/// something each test class has to remember.
/// </para>
/// </summary>
public class KestrelWebAppFactory<TEntryPoint> : Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory<TEntryPoint>
    where TEntryPoint : class
{
    public KestrelWebAppFactory()
        : base("KESTREL_WEBAPP_URL", new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false"))
    {
        Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard.EnsureExplicitTestDatabase();
    }
}
