using System.Collections.Generic;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Thin subclass over the shared <see cref="Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory{TEntryPoint}"/>:
/// the <c>KESTREL_WEBAPP_URL</c> override variable, and <see cref="Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService"/> disabled.
/// The sync would otherwise fire real provider calls against shared test data on every host start (see <see cref="Keeptrack.WebApi.AppConfiguration.IsReferenceSyncEnabled"/>).
/// <para>
/// <c>ReferenceData:VideoGameProvider</c> is pinned to <c>igdb</c> rather than inherited from <c>appsettings.Development.json</c>,
/// so the suite doesn't drift with a deployment choice.
/// Every video game reference test is written against IGDB, including <c>VideoGameReferenceMatchSmokeTest</c>,
/// which requires <c>Igdb__ClientId</c> and <c>Igdb__ClientSecret</c> but not <c>Rawg__ApiKey</c>.
/// </para>
/// <para>
/// Every fixture in this project routes through here, so the database is settled in the constructor.
/// The name comes from <see cref="IntegrationTestDatabase"/>, is pushed into the host's configuration so no appsettings fallback reaches <c>keeptrack_dev</c>,
/// and <see cref="Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard"/> vouches for it.
/// Never writing to the developer's database is then a property of the host rather than of each test class or IDE setting.
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
    /// For a fixture needing the same host with something else configured (<see cref="ProviderlessWebAppFactory"/>),
    /// so the sync-disabling override above is never restated and can't drift.
    /// </summary>
    protected KestrelWebAppFactory(KeyValuePair<string, string?>[] configOverrides)
        : base("KESTREL_WEBAPP_URL",
        [
            new("Features:IsReferenceSyncEnabled", "false"),
            new("Infrastructure:MongoDB:DatabaseName", IntegrationTestDatabase.Name),
            new("ReferenceData:VideoGameProvider", "igdb"),
            .. configOverrides
        ])
    {
        Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard.EnsureTestDatabaseName(IntegrationTestDatabase.Name);
    }
}
