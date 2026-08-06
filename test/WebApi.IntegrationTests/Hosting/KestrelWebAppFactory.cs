using System.Collections.Generic;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Thin subclass over the shared <see cref="Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory{TEntryPoint}"/>,
/// preserving this project's exact pre-extraction behavior: the <c>KESTREL_WEBAPP_URL</c> override variable, and
/// disabling <see cref="Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService"/> so it doesn't fire real
/// TMDB calls against shared test data on every host start-up (see <see cref="Keeptrack.WebApi.AppConfiguration.IsReferenceSyncEnabled"/>).
/// <para>
/// Every fixture in this project routes through here, which is why the database is settled in the constructor:
/// the name comes from <see cref="IntegrationTestDatabase"/> (defaulted, not required), it is pushed into the
/// host's configuration so no appsettings fallback can reach <c>keeptrack_dev</c>, and
/// <see cref="Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard"/> vouches for the name this run will really
/// use. "This suite never writes to the developer's own database" is a property of the host itself rather than
/// something each test class - or each developer's IDE settings - has to get right.
/// </para>
/// </summary>
public class KestrelWebAppFactory<TEntryPoint> : Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory<TEntryPoint>
    where TEntryPoint : class
{
    public KestrelWebAppFactory()
        : this([])
    {
    }

    /// <summary>
    /// For a fixture that needs the same host with something else configured
    /// (<see cref="ProviderlessWebAppFactory"/>), so the sync-disabling override above is never restated -
    /// a second copy of it is exactly how the two would drift apart.
    /// </summary>
    protected KestrelWebAppFactory(KeyValuePair<string, string?>[] configOverrides)
        : base("KESTREL_WEBAPP_URL",
        [
            new("Features:IsReferenceSyncEnabled", "false"),
            new("Infrastructure:MongoDB:DatabaseName", IntegrationTestDatabase.Name),
            .. configOverrides
        ])
    {
        Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard.EnsureTestDatabaseName(IntegrationTestDatabase.Name);
    }
}
