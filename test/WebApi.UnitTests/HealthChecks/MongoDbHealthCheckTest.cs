using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Moq;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.HealthChecks;

[Trait("Category", "UnitTests")]
public class MongoDbHealthCheckTest
{
    private readonly Mock<IMongoDatabase> _database = new();

    private MongoDbHealthCheck CreateSut() => new(_database.Object);

    [Fact]
    public async Task CheckHealthAsync_ReturnsHealthy_WhenThePingCommandSucceeds()
    {
        _database
            .Setup(x => x.RunCommandAsync<BsonDocument>(It.IsAny<Command<BsonDocument>>(), It.IsAny<ReadPreference>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new BsonDocument("ok", 1));

        var result = await CreateSut().CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    /// <summary>
    /// Covers both a transport-level failure (server unreachable) and a command-level one (e.g. the
    /// configured database name isn't one the connection string's user is authorized against) - both
    /// surface the same way here, as an exception out of RunCommandAsync.
    /// </summary>
    [Fact]
    public async Task CheckHealthAsync_ReturnsUnhealthy_WhenThePingCommandThrows()
    {
        var exception = new InvalidOperationException("not authorized on keeptrack to execute command");
        _database
            .Setup(x => x.RunCommandAsync<BsonDocument>(It.IsAny<Command<BsonDocument>>(), It.IsAny<ReadPreference>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await CreateSut().CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Exception.Should().BeSameAs(exception);
    }
}
