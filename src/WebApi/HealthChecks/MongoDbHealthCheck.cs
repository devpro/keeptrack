using Microsoft.Extensions.Diagnostics.HealthChecks;
using MongoDB.Driver;

namespace Keeptrack.WebApi.HealthChecks;

/// <summary>
/// Runs a <c>ping</c> against the configured <see cref="IMongoDatabase"/> - not just "is a MongoDB
/// server reachable somewhere", but specifically the connection string, credentials and
/// <c>Infrastructure__MongoDB__DatabaseName</c> this instance is actually configured with. A
/// database name the connection string's user isn't authorized against (a real incident once, e.g. a
/// MongoDB Atlas user scoped to a different database) fails at command level, not transport level -
/// a plain "can we open a socket" check would report healthy right up until the first real query.
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
