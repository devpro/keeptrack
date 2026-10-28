using Keeptrack.Testing.Shared.Authentication;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The same host validating local tokens whatever the run's mode, so a Firebase run still proves the local path (see docs/authentication.md).
/// </summary>
public sealed class LocalAuthenticationWebAppFactory() : KestrelWebAppFactory<Program>(TestAuthentication.LocalWebApiConfiguration());
