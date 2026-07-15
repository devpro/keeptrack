using System.Collections.Generic;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Thin subclass over the shared <see cref="Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory{TEntryPoint}"/>,
/// preserving this project's exact pre-extraction behavior: the <c>KESTREL_WEBAPP_URL</c> override variable, and
/// disabling <see cref="Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService"/> so it doesn't fire real
/// TMDB calls against shared test data on every host start-up (see <see cref="Keeptrack.WebApi.AppConfiguration.IsReferenceSyncEnabled"/>).
/// </summary>
public class KestrelWebAppFactory<TEntryPoint> : Keeptrack.Testing.Shared.Hosting.KestrelWebAppFactory<TEntryPoint>
    where TEntryPoint : class
{
    public KestrelWebAppFactory()
        : base("KESTREL_WEBAPP_URL", new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false"))
    {
    }
}
