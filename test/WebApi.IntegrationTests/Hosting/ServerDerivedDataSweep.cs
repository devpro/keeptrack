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
/// Removes, once the whole run is over, the documents a test caused the *server* to write on its own schedule
/// rather than creating itself - the one class of leftover <c>DatabaseTestBase.TrackCleanup</c> cannot cover.
/// <para>
/// A background pass writes minutes after the test that started it has finished, so there is nothing to
/// register at the moment of creation: at cleanup time those documents don't exist yet, and the pass stops only
/// when the host does. That is how 39 real TMDB ranking entries came to sit in <c>keeptrack_integrationtests</c>,
/// where they were anything but inert - the shared, owner-less ranking every caller reads, which broke
/// <c>ExploreSmokeTest</c> in the Playwright suite (its premise is that a seeded ranking *is* the ranking; it
/// saw its own 26 suggestions interleaved with 18 real films).
/// </para>
/// <para>
/// The tests that caused it are fixed at the source rather than mopped up here: the endpoint-contract tests
/// that start a sync job now run on <see cref="ProviderlessWebAppFactory"/> and write nothing at all, so a
/// normal run leaves this sweep with no work to do. It stays as the backstop for the one test that genuinely
/// wants a live pass (<c>ReferenceSyncPollingResourceTest</c>, opt-in) and for any future test that starts one -
/// because "no leftovers, even on failure" cannot rest on every such test remembering.
/// </para>
/// <para>
/// An assembly fixture is the only place this is airtight. It disposes after every test class and every
/// <see cref="KestrelWebAppFactory{TEntryPoint}"/> with it, so the passes still writing during the run
/// (they are cancelled by <c>ApplicationStopping</c> when their host goes down) have all stopped - nothing can
/// write behind the sweep. A per-test wait would have to block on a pass whose only end is that shutdown.
/// </para>
/// <para>
/// Deleting rather than restoring is safe for exactly these collections and no others: they hold derived state
/// that the server rebuilds from scratch on its own schedule (a weekly ranking, a mutual-exclusion lease), no
/// tenant data points at them, and <see cref="TestDatabaseGuard"/> has already refused to let this suite run
/// against anything but a dedicated test database. <c>provider_quota</c> is deliberately *not* swept: it is the
/// ledger of OMDb calls genuinely spent against a real 1000/day allowance, so wiping it would let the next run
/// overspend the limit it exists to enforce - and its own TTL index expires it anyway.
/// </para>
/// </summary>
public sealed class ServerDerivedDataSweep : IAsyncLifetime
{
    /// <summary>Collections written by a background pass, not by a test's own request.</summary>
    private static readonly string[] s_derivedCollections = ["explore_catalogue", "lease"];

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Nothing here may throw. This is an assembly fixture, so an exception on the way in or out is reported
    /// against *every* test in the suite - a cleanup that turns 198 passes into 198 failures is worse than the
    /// leftovers it exists to remove, and the run is over by the time it matters anyway. The guard is re-checked
    /// here rather than trusted from the host, because this is the one place that deletes without going through
    /// one.
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
    /// The same connection the in-process host uses, falling back to the local default every other component
    /// here does. The database *name* is never guessed - it comes from <see cref="IntegrationTestDatabase"/>,
    /// the one place this suite resolves it, so the sweep can only ever empty the database the tests filled.
    /// </summary>
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("Infrastructure__MongoDB__ConnectionString") is { Length: > 0 } value
            ? value
            : "mongodb://localhost:27017";
}
