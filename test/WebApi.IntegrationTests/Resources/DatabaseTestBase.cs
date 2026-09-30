using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Base for every test in this suite that writes to the shared test database, holding the one thing all of
/// them need: a registry of "undo this" actions that runs when the test ends, whether it passed or failed.
/// <para>
/// The suite runs against a real, long-lived MongoDB rather than a per-test throwaway one, so a test that
/// leaves documents behind isn't just untidy - the natural-key and external-id uniqueness indexes
/// (<c>scripts/mongodb-create-index.js</c>) mean yesterday's leftover makes today's run fail with a
/// duplicate-key error. Leaving the database as we found it is what keeps the suite re-runnable.
/// </para>
/// <para>
/// Registration replaces the per-test <c>try/finally</c> this suite used to write. A <c>finally</c> only
/// covers what was created before the <c>try</c> opened, so the common "create two items, then open the
/// try" shape leaked its fixtures whenever the second create failed. Registering at the moment of creation
/// has no such gap, and it removes the same cleanup block repeated in ~40 files.
/// </para>
/// </summary>
public abstract class DatabaseTestBase(KestrelWebAppFactory<Program> factory)
    : IClassFixture<KestrelWebAppFactory<Program>>, IAsyncLifetime
{
    private readonly List<Func<Task>> _cleanups = [];

    /// <summary>
    /// Exposes the factory to subclasses that need a DI scope (e.g. to seed data directly through a
    /// repository) - avoids a second, redundant capture of the same constructor parameter as its own field.
    /// </summary>
    protected KestrelWebAppFactory<Program> Factory => factory;

    /// <summary>
    /// Registers an action that undoes something this test created. Call it as soon as the thing exists,
    /// not at the end of the test.
    /// </summary>
    protected void TrackCleanup(Func<Task> cleanup) => _cleanups.Add(cleanup);

    /// <summary>
    /// Registers a raw MongoDB document for deletion by <c>_id</c> - for collections reached through a
    /// purpose-built repository with no delete method of its own (the owner-less reference collections,
    /// <c>lease</c>, <c>background_job</c>).
    /// <para>
    /// The filter is built over <see cref="BsonDocument"/> with the <c>_id</c> explicitly converted to an
    /// <see cref="ObjectId"/> when the string is one, because getting this wrong is silent. An earlier
    /// version of this cleanup filtered a mapped entity collection by the string field name <c>"_id"</c>,
    /// which compares a BSON string against a document whose <c>_id</c> is an ObjectId: it matches nothing,
    /// deletes nothing, and reports success. That is exactly how 65 stray <c>Export Test Actor</c>
    /// documents accumulated while the tests that created them kept passing. Collections whose id is a
    /// genuine string (<c>lease</c>, <c>background_job</c>) simply don't parse as an ObjectId and are
    /// filtered as strings, so one helper covers both.
    /// </para>
    /// </summary>
    protected void TrackDocument(string collectionName, string? id)
    {
        if (string.IsNullOrEmpty(id)) return;

        TrackCleanup(async () =>
        {
            var collection = factory.Services.GetRequiredService<IMongoDatabase>().GetCollection<BsonDocument>(collectionName);
            var documentId = ObjectId.TryParse(id, out var objectId) ? (BsonValue)objectId : id;
            await collection.DeleteOneAsync(Builders<BsonDocument>.Filter.Eq("_id", documentId), CancellationToken.None);
        });
    }

    /// <summary>
    /// Registers every document matching a filter for deletion - for the owner-scoped singletons that have
    /// no id a test can hold onto (<c>user_preference</c> is written by the server on the caller's behalf,
    /// so the test only ever knows the owner it belongs to).
    /// </summary>
    protected void TrackDocumentsWhere(string collectionName, FilterDefinition<BsonDocument> filter)
    {
        TrackCleanup(async () =>
        {
            var collection = factory.Services.GetRequiredService<IMongoDatabase>().GetCollection<BsonDocument>(collectionName);
            await collection.DeleteManyAsync(filter, CancellationToken.None);
        });
    }

    public virtual ValueTask InitializeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Runs every registered cleanup in reverse order of registration, so a child is removed before the
    /// parent it references.
    /// <para>
    /// The list is drained rather than indexed over a cached count, because a cleanup may itself register
    /// more: <c>TrackResourcesMatching</c> can only discover what a bulk import created by querying for it
    /// at cleanup time, and then registers each id it found. Draining runs those too, still last-in-first-out.
    /// </para>
    /// <para>
    /// Two further deliberate choices. Cleanups run under <see cref="CancellationToken.None"/>, never
    /// <c>TestContext.Current.CancellationToken</c>: that token is cancelled exactly when a test times out
    /// or the run is interrupted, which is precisely when leftovers are most likely and cleanup matters
    /// most. And one failing cleanup never skips the rest - failures are collected and reported together,
    /// so a broken cleanup surfaces as a test error instead of quietly leaving data behind.
    /// </para>
    /// </summary>
    public virtual async ValueTask DisposeAsync()
    {
        List<Exception>? failures = null;

        while (_cleanups.Count > 0)
        {
            var cleanup = _cleanups[^1];
            _cleanups.RemoveAt(_cleanups.Count - 1);

            try
            {
                await cleanup();
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(exception);
            }
        }

        GC.SuppressFinalize(this);

        if (failures is not null)
        {
            throw new AggregateException(
                $"{failures.Count} test cleanup action(s) failed - the test database may still hold data created by this test.",
                failures);
        }
    }
}
