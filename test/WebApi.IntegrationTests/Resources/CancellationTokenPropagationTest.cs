using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Proves the <see cref="CancellationToken"/> a repository method now accepts actually reaches the MongoDB
/// driver, rather than just compiling.
/// A mocked repository could never prove this: it is real driver behavior, not application logic.
/// <para>
/// Movies stand in for the whole base class, same convention as <see cref="MalformedIdResourceTest"/>: the
/// forwarding happens once in <c>MongoDbRepositoryBase</c> and is identical for every repository built on it.
/// </para>
/// </summary>
public class CancellationTokenPropagationTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindOneAsync_ThrowsOperationCanceled_ForAnAlreadyCancelledToken()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => repository.FindOneAsync("0123456789abcdef01234567", "irrelevant-owner", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FindAllAsync_ThrowsOperationCanceled_ForAnAlreadyCancelledToken()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => repository.FindAllAsync("irrelevant-owner", 1, 10, null, new() { OwnerId = "irrelevant-owner", Title = "" }, cancellationToken: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
