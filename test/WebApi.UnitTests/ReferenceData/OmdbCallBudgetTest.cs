using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Every other test in this suite fakes <see cref="IOmdbCallBudget"/> itself (<see cref="FakeOmdbCallBudget"/>), so none of them exercise <see cref="OmdbCallBudget"/>'s own logic: the split between <see cref="OmdbSettings.InteractiveReserve"/> and the full <see cref="OmdbSettings.DailyCallBudget"/>, the asymmetric exhaustion rule (interactive running out implies background did too, never the reverse, since background's ceiling is always the lower or equal one), and the per-process short-circuit that skips a database round trip once a priority is known spent for the day.
/// This pins that logic against a fake <see cref="IProviderQuotaRepository"/> standing in for the real MongoDB-backed counter.
/// </summary>
[Trait("Category", "UnitTests")]
public class OmdbCallBudgetTest
{
    [Fact]
    public void Ceiling_ReservesTheInteractiveReserve_OnlyForBackgroundWork()
    {
        var budget = NewBudget(new FakeProviderQuotaRepository(), dailyCallBudget: 1000, interactiveReserve: 50);

        budget.Ceiling(OmdbCallPriority.Interactive).Should().Be(1000);
        budget.Ceiling(OmdbCallPriority.Background).Should().Be(950);
    }

    [Fact]
    public async Task TryReserveAsync_StopsBackgroundShortOfTheReserve_WhileInteractiveCanStillReachIt()
    {
        var repository = new FakeProviderQuotaRepository();
        var budget = NewBudget(repository, dailyCallBudget: 10, interactiveReserve: 3);

        for (var i = 0; i < 7; i++)
        {
            (await budget.TryReserveAsync(OmdbCallPriority.Background, TestContext.Current.CancellationToken)).Should().BeTrue();
        }

        // background's ceiling (10 - 3) is now spent
        (await budget.TryReserveAsync(OmdbCallPriority.Background, TestContext.Current.CancellationToken)).Should().BeFalse();
        // interactive's ceiling (the full 10) still has headroom against the very same shared counter
        (await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().BeTrue();
    }

    [Fact]
    public async Task IsExhausted_BackgroundRunningOutDoesNotImplyInteractiveIsExhausted()
    {
        var repository = new FakeProviderQuotaRepository();
        var budget = NewBudget(repository, dailyCallBudget: 10, interactiveReserve: 3);
        for (var i = 0; i < 7; i++) await budget.TryReserveAsync(OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        // the 8th call is refused and marks background exhausted for the day
        (await budget.TryReserveAsync(OmdbCallPriority.Background, TestContext.Current.CancellationToken)).Should().BeFalse();

        budget.IsExhausted(OmdbCallPriority.Background).Should().BeTrue();
        budget.IsExhausted(OmdbCallPriority.Interactive).Should().BeFalse("a heavy batch day must never make a user-facing lookup look spent");
    }

    [Fact]
    public async Task IsExhausted_InteractiveRunningOutImpliesBackgroundIsAlsoExhausted()
    {
        var repository = new FakeProviderQuotaRepository();
        // no reserve carved out, so both priorities share the same ceiling
        var budget = NewBudget(repository, dailyCallBudget: 2, interactiveReserve: 0);
        await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);
        await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        (await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().BeFalse();

        budget.IsExhausted(OmdbCallPriority.Interactive).Should().BeTrue();
        // background's ceiling is never higher than interactive's, so interactive being spent means background is too
        budget.IsExhausted(OmdbCallPriority.Background).Should().BeTrue();
    }

    [Fact]
    public async Task TryReserveAsync_StopsAskingTheRepository_OnceAPriorityIsKnownExhaustedLocally()
    {
        var repository = new FakeProviderQuotaRepository();
        var budget = NewBudget(repository, dailyCallBudget: 1, interactiveReserve: 0);
        (await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().BeTrue();
        (await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().BeFalse();
        var callsSoFar = repository.TryConsumeCallCount;

        // a batch loop calling this once per remaining item must not cost a database round trip per call
        (await budget.TryReserveAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().BeFalse();

        repository.TryConsumeCallCount.Should().Be(callsSoFar, "once exhausted locally, no further reservation should reach the repository");
    }

    [Fact]
    public async Task MarkLimitReachedAsync_ExhaustsBothPriorities_AndWritesThroughToTheRepositoryOnce()
    {
        var repository = new FakeProviderQuotaRepository();
        var budget = NewBudget(repository, dailyCallBudget: 1000, interactiveReserve: 50);

        await budget.MarkLimitReachedAsync(TestContext.Current.CancellationToken);

        budget.IsExhausted(OmdbCallPriority.Interactive).Should().BeTrue();
        budget.IsExhausted(OmdbCallPriority.Background).Should().BeTrue();
        repository.ExhaustCallCount.Should().Be(1);
    }

    [Fact]
    public async Task GetRemainingAsync_ReportsZero_WhenNoApiKeyIsConfigured()
    {
        var budget = NewBudget(new FakeProviderQuotaRepository(), apiKey: null);

        (await budget.GetRemainingAsync(OmdbCallPriority.Interactive, TestContext.Current.CancellationToken)).Should().Be(0);
    }

    private static OmdbCallBudget NewBudget(FakeProviderQuotaRepository repository, int dailyCallBudget = 1000, int interactiveReserve = 50, string? apiKey = "key")
    {
        var services = new ServiceCollection();
        services.AddSingleton<IProviderQuotaRepository>(repository);
        var provider = services.BuildServiceProvider();
        var settings = new OmdbSettings { ApiKey = apiKey, DailyCallBudget = dailyCallBudget, InteractiveReserve = interactiveReserve };
        return new OmdbCallBudget(provider.GetRequiredService<IServiceScopeFactory>(), settings, NullLogger<OmdbCallBudget>.Instance);
    }

    /// <summary>In-memory stand-in for the MongoDB-backed counter, so this file can pin <see cref="OmdbCallBudget"/>'s own logic without a real database.</summary>
    private sealed class FakeProviderQuotaRepository : IProviderQuotaRepository
    {
        private readonly Dictionary<(string Provider, DateOnly Day), int> _used = new();

        public int TryConsumeCallCount { get; private set; }

        public int ExhaustCallCount { get; private set; }

        public Task<bool> TryConsumeAsync(string provider, DateOnly day, int ceiling, CancellationToken cancellationToken = default)
        {
            TryConsumeCallCount++;
            var key = (provider, day);
            var used = _used.GetValueOrDefault(key);
            if (used >= ceiling) return Task.FromResult(false);
            _used[key] = used + 1;
            return Task.FromResult(true);
        }

        public Task<int> GetUsedAsync(string provider, DateOnly day, CancellationToken cancellationToken = default) =>
            Task.FromResult(_used.GetValueOrDefault((provider, day)));

        public Task ExhaustAsync(string provider, DateOnly day, int total, CancellationToken cancellationToken = default)
        {
            ExhaustCallCount++;
            var key = (provider, day);
            _used[key] = Math.Max(_used.GetValueOrDefault(key), total);
            return Task.CompletedTask;
        }
    }
}
