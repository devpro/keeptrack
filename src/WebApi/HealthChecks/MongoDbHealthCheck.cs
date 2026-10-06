using Microsoft.Extensions.Diagnostics.HealthChecks;
using MongoDB.Driver;

namespace Keeptrack.WebApi.HealthChecks;

/// <summary>
/// Runs a <c>ping</c> against the configured <see cref="IMongoDatabase"/>, checking this instance's connection string, credentials and database name, not only that a server is reachable.
/// A database the user is not authorized on, such as an Atlas user scoped to another database, fails at command level, so a socket check would report healthy until the first real query.
/// </summary>
public sealed class MongoDbHealthCheck(IMongoDatabase database) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await database.RunCommandAsync<BsonDocument>(new BsonDocument("ping", 1), cancellationToken: cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("MongoDB is unreachable, or the configured database/credentials are invalid.", ex);
        }
    }
}
