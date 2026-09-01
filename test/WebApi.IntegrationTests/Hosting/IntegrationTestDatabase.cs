using System;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The MongoDB database this suite runs against: <c>Infrastructure__MongoDB__DatabaseName</c> when it is set,
/// and <see cref="DefaultName"/> otherwise.
/// <para>
/// Defaulted rather than required, for the same reason the e2e suite defaults its own (see
/// <c>End2EndConfiguration.DatabaseName</c>): an IDE sets test environment variables once for the whole
/// solution, so a variable both suites read can only ever give them the same database - and a developer who
/// removes it to stop them sharing one gets 198 failures instead, because the guard's fallback was to refuse
/// the run rather than to pick something safe. The two are now isolated by construction and neither needs the
/// variable at all; setting it still points this suite wherever you want.
/// </para>
/// <para>
/// This does not weaken <see cref="Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard"/>: what it exists to
/// prevent is the *silent* fallback to the host's own <c>appsettings.Development.json</c> (i.e.
/// <c>keeptrack_dev</c>, real data), and the name resolved here is pushed into the host's configuration
/// precisely so that fallback can't happen. An explicitly configured <c>dev</c>/<c>prod</c> name still fails
/// fast.
/// </para>
/// </summary>
public static class IntegrationTestDatabase
{
    public const string DefaultName = "keeptrack_integrationtests";

    private const string DatabaseNameVariable = "Infrastructure__MongoDB__DatabaseName";

    public static string Name =>
        Environment.GetEnvironmentVariable(DatabaseNameVariable) is { Length: > 0 } value ? value : DefaultName;
}
