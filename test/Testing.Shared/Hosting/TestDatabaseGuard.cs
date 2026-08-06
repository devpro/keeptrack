using System;

namespace Keeptrack.Testing.Shared.Hosting;

/// <summary>
/// Fail-fast check that a suite hosting the real <c>WebApi</c> in-process is pointed at a dedicated test
/// database rather than the developer's own data.
/// <para>
/// This exists because the failure it prevents is silent and destructive. The in-process host runs as
/// <c>Development</c>, so when <c>Infrastructure__MongoDB__DatabaseName</c> isn't exported the host falls
/// straight back to <c>src/WebApi/appsettings.Development.json</c> - i.e. <c>keeptrack_dev</c>, the database
/// the developer actually browses in the app. Nothing errors; the whole suite just creates, mutates and
/// deletes documents in real data.
/// </para>
/// <para>
/// It's easy to hit by accident rather than by carelessness: the documented way to run a *filtered* subset
/// (see CLAUDE.md) is to export the runsettings' variables into the shell yourself, because
/// <c>--settings</c> can't be combined with <c>--filter-method</c>. Forget that one step and the run lands
/// on <c>keeptrack_dev</c>. That is exactly how this repository's dev database ended up holding leftover
/// <c>test-lease-*</c>, <c>Export Test Actor</c> and <c>E2e Smoke *</c> documents.
/// </para>
/// </summary>
public static class TestDatabaseGuard
{
    private const string DatabaseNameVariable = "Infrastructure__MongoDB__DatabaseName";

    /// <summary>
    /// Substrings that mark a database as a real, non-throwaway one. Deliberately a denylist of "this is
    /// somebody's data" markers rather than an allowlist of blessed test names: a new suite pointing at
    /// <c>keeptrack_something_new</c> should just work, while pointing at <c>keeptrack_dev</c> or a
    /// production database must never be the accidental default.
    /// </summary>
    private static readonly string[] ProtectedDatabaseMarkers = ["dev", "prod", "staging", "preprod"];

    /// <summary>
    /// Throws unless an explicit, test-looking database name was supplied through the environment.
    /// Call this before the host is built, so the run stops with an actionable message instead of writing
    /// to the wrong database.
    /// </summary>
    public static void EnsureExplicitTestDatabase()
        => EnsureTestDatabaseName(Environment.GetEnvironmentVariable(DatabaseNameVariable));

    /// <summary>
    /// The same check against a name the caller resolved itself, for a suite that picks its own database rather
    /// than inheriting the ambient variable (see <c>End2EndConfiguration.DatabaseName</c>). Checking the
    /// variable there would vouch for a name the run isn't going to use.
    /// </summary>
    public static void EnsureTestDatabaseName(string? databaseName)
    {
        if (string.IsNullOrWhiteSpace(databaseName))
        {
            throw new InvalidOperationException(
                $"{DatabaseNameVariable} is not set, so this test run would fall back to the host's own " +
                "appsettings.Development.json database (keeptrack_dev) and create/delete documents in real data. " +
                "Run the suite with '--settings Local.runsettings', or export the runsettings' environment " +
                "variables into your shell first when you need to combine a filter with a run (see CLAUDE.md).");
        }

        foreach (var marker in ProtectedDatabaseMarkers)
        {
            if (databaseName.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"{DatabaseNameVariable} is set to '{databaseName}', which looks like a real database, not a " +
                    "throwaway test one. The suite creates and deletes documents, so point it at a dedicated " +
                    "database (e.g. keeptrack_integrationtests) instead.");
            }
        }
    }
}
