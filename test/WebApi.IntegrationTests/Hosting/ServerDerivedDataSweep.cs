using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Testing.Shared.Hosting;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

[assembly: AssemblyFixture(typeof(Keeptrack.WebApi.IntegrationTests.Hosting.ServerDerivedDataSweep))]

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Removes, once the run is over, the documents a test made the <i>server</i> write on its own schedule, the one leftover <c>DatabaseTestBase.TrackCleanup</c> can't cover.
/// <para>
/// A background pass writes minutes after the test that started it, so nothing can be registered at creation: at cleanup time those documents don't exist yet, and the pass stops only with the host.
/// Real TMDB ranking entries left in <c>keeptrack_integrationtests</c> are anything but inert, being the shared ranking every caller reads, and they break <c>ExploreSmokeTest</c>, whose premise is that a seeded ranking is the ranking.
/// </para>
/// <para>
/// The endpoint-contract tests that start a sync job run on <see cref="ProviderlessWebAppFactory"/> and write nothing, so a normal run leaves this sweep nothing to do.
/// It is the backstop for the one test wanting a live pass (<c>ReferenceSyncPollingResourceTest</c>, opt-in) and any future one, since "no leftovers, even on failure" can't rest on every such test remembering.
/// </para>
/// <para>
/// An assembly fixture is the only airtight place.
/// It disposes after every test class and every <see cref="KestrelWebAppFactory{TEntryPoint}"/>, so the passes still writing (cancelled by <c>ApplicationStopping</c> when their host goes down) have stopped, and nothing writes behind the sweep.
/// A per-test wait would block on a pass whose only end is that shutdown.
/// </para>
/// <para>
/// Deleting rather than restoring is safe for these collections only: they hold derived state the server rebuilds on its own schedule (a weekly ranking, a mutual-exclusion lease), and no tenant data points at them.
/// <see cref="TestDatabaseGuard"/> has already refused anything but a dedicated test database.
/// <c>provider_quota</c> is <i>not</i> swept, being the ledger of OMDb calls spent against a real 1000/day allowance, so wiping it would let the next run overspend, and its TTL index expires it anyway.
/// </para>
/// </summary>
public sealed class ServerDerivedDataSweep : IAsyncLifetime
{
    /// <summary>Collections written by a background pass, not by a test's own request.</summary>
    private static readonly string[] s_derivedCollections = ["explore_catalogue", "lease"];

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Nothing here may throw.
    /// As an assembly fixture, an exception on the way in or out is reported against every test in the suite, and turning every pass into a failure is worse than the leftovers.
    /// The guard is re-checked here rather than trusted from the host, since this is the one place deleting without going through one.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            TestDatabaseGuard.EnsureTestDatabaseName(IntegrationTestDatabase.Name);

            var database = new MongoClient(ConnectionString).GetDatabase(IntegrationTestDatabase.Name);
            var removed = new List<string>();

            foreach (var collectionName in s_derivedCollections)
            {
                var result = await database.GetCollection<BsonDocument>(collectionName)
                    .DeleteManyAsync(Builders<BsonDocument>.Filter.Empty, CancellationToken.None);

                if (result.DeletedCount > 0)
                {
                    removed.Add($"{collectionName}: {result.DeletedCount}");
                }
            }

            if (removed.Count > 0)
            {
                Console.WriteLine($"Swept server-derived documents left by this run - {string.Join(", ", removed)}.");
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Could not sweep server-derived documents: {exception.Message}");
        }
    }

    /// <summary>
    /// The same connection the in-process host uses, falling back to the local default every other component here does.
    /// The database name is never guessed but comes from <see cref="IntegrationTestDatabase"/>, the one place this suite resolves it, so the sweep only empties the database the tests filled.
    /// </summary>
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("Infrastructure__MongoDB__ConnectionString") is { Length: > 0 } value
            ? value
            : "mongodb://localhost:27017";
}
