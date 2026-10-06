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
/// Base for every test in this suite writing to the shared test database, holding what all of them need: a registry of "undo this" actions run when the test ends, passed or failed.
/// <para>
/// The suite runs against a real, long-lived MongoDB rather than a throwaway one per test, so a leftover is not only untidy.
/// The natural-key and external-id unique indexes (<c>scripts/mongodb-create-index.js</c>) make yesterday's leftover fail today's run with a duplicate-key error.
/// Leaving the database as it was found keeps the suite re-runnable.
/// </para>
/// <para>
/// Registration is used rather than a per-test <c>try/finally</c>, which covers only what was created before the <c>try</c> opened.
/// "Create two items, then open the try" would leak its fixtures whenever the second create failed, and registering at creation has no such gap.
/// </para>
/// </summary>
public abstract class DatabaseTestBase(KestrelWebAppFactory<Program> factory)
    : IClassFixture<KestrelWebAppFactory<Program>>, IAsyncLifetime
{
    private readonly List<Func<Task>> _cleanups = [];

    /// <summary>
    /// Exposes the factory to subclasses needing a DI scope (to seed data through a repository), rather than a second capture of the same constructor parameter.
    /// </summary>
    protected KestrelWebAppFactory<Program> Factory => factory;

    /// <summary>
    /// Registers an action that undoes something this test created.
    /// Call it as soon as the thing exists, not at the end of the test.
    /// </summary>
    protected void TrackCleanup(Func<Task> cleanup) => _cleanups.Add(cleanup);

    /// <summary>
    /// Registers a raw MongoDB document for deletion by <c>_id</c>, for collections reached through a purpose-built repository with no delete method (the owner-less reference collections, <c>lease</c>, <c>background_job</c>).
    /// <para>
    /// The filter is built over <see cref="BsonDocument"/>, with the <c>_id</c> converted to an <see cref="ObjectId"/> when the string is one, since getting this wrong is silent.
    /// Filtering a mapped entity collection by the string field name <c>"_id"</c> compares a BSON string against an ObjectId: it matches nothing, deletes nothing, and reports success.
    /// Collections whose id is a real string (<c>lease</c>, <c>background_job</c>) don't parse as an ObjectId and are filtered as strings, so one helper covers both.
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
    /// Registers every document matching a filter for deletion, for owner-scoped singletons with no id a test can hold.
    /// The server writes <c>user_preference</c> on the caller's behalf, so the test knows only its owner.
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
    /// Runs every registered cleanup in reverse order of registration, so a child is removed before the parent it references.
    /// <para>
    /// The list is drained rather than indexed over a cached count, since a cleanup may register more: <c>TrackResourcesMatching</c> discovers what a bulk import created by querying at cleanup time, then registers each id found.
    /// Draining runs those too, still last-in-first-out.
    /// </para>
    /// <para>
    /// Two further deliberate choices.
    /// Cleanups run under <see cref="CancellationToken.None"/>, never <c>TestContext.Current.CancellationToken</c>, which is cancelled exactly when a test times out or the run is interrupted, when cleanup matters most.
    /// One failing cleanup never skips the rest: failures are collected and reported together, so a broken cleanup surfaces as a test error instead of quietly leaving data behind.
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
