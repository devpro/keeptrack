using System;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="IProviderQuotaRepository"/> against real MongoDB. The whole point of this repository
/// is that several replicas sharing one rate-limited API key can't collectively overspend it, and that rests
/// entirely on server-side semantics a mock can only restate: a filtered upsert whose ceiling check and
/// increment are one atomic operation, with _id uniqueness turning "already at the ceiling" into a duplicate
/// key rather than a second counter. A read-then-write implementation would pass a mocked test and hand out
/// the same last call to every replica that asked at once.
/// <para>
/// Each test uses its own provider name so parallel classes can't contend, and registers the day's document
/// for cleanup - <c>provider_quota</c> ids are genuine strings (like <c>lease</c>), not ObjectIds.
/// </para>
/// </summary>
public class ProviderQuotaRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    private static readonly DateOnly s_day = new(2026, 8, 3);

    [Fact]
    public async Task TryConsume_CountsUpToTheCeiling_ThenRefuses()
    {
        var repository = Repository();
        var provider = NewProvider();

        (await repository.TryConsumeAsync(provider, s_day, 2, TestContext.Current.CancellationToken)).Should().BeTrue();
        (await repository.TryConsumeAsync(provider, s_day, 2, TestContext.Current.CancellationToken)).Should().BeTrue();
        (await repository.TryConsumeAsync(provider, s_day, 2, TestContext.Current.CancellationToken)).Should().BeFalse();

        (await repository.GetUsedAsync(provider, s_day, TestContext.Current.CancellationToken)).Should().Be(2, "a refused reservation must not be counted");
    }

    [Fact]
    public async Task TryConsume_NeverExceedsTheCeiling_UnderConcurrentReservations()
    {
        var repository = Repository();
        var provider = NewProvider();
        const int ceiling = 20;

        // 50 replicas racing for 20 calls - the check-and-increment has to be one server-side operation, or
        // several of these read the same "19 used" and all decide they may spend
        var granted = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => repository.TryConsumeAsync(provider, s_day, ceiling, TestContext.Current.CancellationToken)));

        granted.Count(g => g).Should().Be(ceiling);
        (await repository.GetUsedAsync(provider, s_day, TestContext.Current.CancellationToken)).Should().Be(ceiling);
    }

    [Fact]
    public async Task TryConsume_KeepsADifferentDaysAllowanceSeparate()
    {
        var repository = Repository();
        var provider = NewProvider();
        var nextDay = s_day.AddDays(1);
        TrackDocument("provider_quota", $"{provider}:{nextDay:yyyy-MM-dd}");

        (await repository.TryConsumeAsync(provider, s_day, 1, TestContext.Current.CancellationToken)).Should().BeTrue();
        (await repository.TryConsumeAsync(provider, s_day, 1, TestContext.Current.CancellationToken)).Should().BeFalse();

        // the day is part of the key, so the allowance renews with no reset job and no clock coordination
        (await repository.TryConsumeAsync(provider, nextDay, 1, TestContext.Current.CancellationToken)).Should().BeTrue();
    }

    [Fact]
    public async Task TryConsume_RefusesWithoutWriting_WhenTheCallerHasNoAllowanceAtAll()
    {
        var repository = Repository();
        var provider = NewProvider();

        // a ceiling of 0 is what a batch caller sees once the whole budget is reserved for interactive work
        (await repository.TryConsumeAsync(provider, s_day, 0, TestContext.Current.CancellationToken)).Should().BeFalse();

        (await repository.GetUsedAsync(provider, s_day, TestContext.Current.CancellationToken)).Should().Be(0);
    }

    [Fact]
    public async Task Exhaust_StopsFurtherReservations_ForTheRestOfTheDay()
    {
        var repository = Repository();
        var provider = NewProvider();

        // the provider itself reported the limit reached, well before the local count expected it
        await repository.ExhaustAsync(provider, s_day, 1000, TestContext.Current.CancellationToken);

        (await repository.TryConsumeAsync(provider, s_day, 1000, TestContext.Current.CancellationToken)).Should().BeFalse();
        (await repository.GetUsedAsync(provider, s_day, TestContext.Current.CancellationToken)).Should().Be(1000);
    }

    [Fact]
    public async Task Exhaust_NeverLowersACountThatIsAlreadyHigher()
    {
        var repository = Repository();
        var provider = NewProvider();
        for (var i = 0; i < 5; i++) await repository.TryConsumeAsync(provider, s_day, 100, TestContext.Current.CancellationToken);

        await repository.ExhaustAsync(provider, s_day, 3, TestContext.Current.CancellationToken);

        // lowering it would hand back calls the provider has just told us don't exist
        (await repository.GetUsedAsync(provider, s_day, TestContext.Current.CancellationToken)).Should().Be(5);
    }

    [Fact]
    public async Task GetUsed_ReportsZero_ForADayNothingWasSpentOn()
    {
        (await Repository().GetUsedAsync(NewProvider(), s_day, TestContext.Current.CancellationToken)).Should().Be(0);
    }

    private IProviderQuotaRepository Repository()
    {
        var scope = Factory.Services.CreateScope();
        TrackCleanup(() =>
        {
            scope.Dispose();
            return Task.CompletedTask;
        });
        return scope.ServiceProvider.GetRequiredService<IProviderQuotaRepository>();
    }

    /// <summary>
    /// A per-test provider name, registered for cleanup up front (the document's _id is derived from it), so
    /// parallel classes never share a counter and no test leaves one behind.
    /// </summary>
    private string NewProvider()
    {
        var provider = $"test-provider-{Guid.NewGuid():N}";
        TrackDocument("provider_quota", $"{provider}:{s_day:yyyy-MM-dd}");
        return provider;
    }
}
