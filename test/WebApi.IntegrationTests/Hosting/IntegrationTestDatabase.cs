using System;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The MongoDB database this suite runs against: <c>Infrastructure__MongoDB__DatabaseName</c> when it is set, and <see cref="DefaultName"/> otherwise.
/// <para>
/// Defaulted rather than required, like the e2e suite's (see <c>End2EndConfiguration.DatabaseName</c>):
/// an IDE sets test variables once for the solution, so a variable both suites read gives them the same database.
/// The two are isolated by construction and neither needs the variable, which still points this suite at another database when set.
/// </para>
/// <para>
/// This doesn't weaken <see cref="Keeptrack.Testing.Shared.Hosting.TestDatabaseGuard"/>,
/// which prevents the silent fallback to the host's <c>appsettings.Development.json</c> (<c>keeptrack_dev</c>, real data).
/// The name resolved here is pushed into the host's configuration so that fallback can't happen.
/// An explicitly configured <c>dev</c>/<c>prod</c> name still fails fast.
/// </para>
/// </summary>
public static class IntegrationTestDatabase
{
    public const string DefaultName = "keeptrack_integrationtests";

    private const string DatabaseNameVariable = "Infrastructure__MongoDB__DatabaseName";

    public static string Name =>
        Environment.GetEnvironmentVariable(DatabaseNameVariable) is { Length: > 0 } value ? value : DefaultName;
}
