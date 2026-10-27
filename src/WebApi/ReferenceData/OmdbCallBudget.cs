using System.Threading;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single gate every OMDb call passes through, enforcing the key's daily quota across replicas.
/// <para>
/// OMDb's free tier is 1000 calls a day, and an exhausted key gets a 401 rather than data, so calling blindly costs a pass of failures and blocks the next call that mattered.
/// Two consumers spend the key on the same tick, the reference sync's IMDb backfill then Explore's, and this lets each see what the other spent.
/// </para>
/// <para>
/// The count lives in MongoDB (<see cref="IProviderQuotaRepository"/>), since interactive resolves land on any replica,
/// and a counter in the process would let each spend the whole allowance.
/// A call is reserved before it is made, so an over-count is possible and an under-count is not, the safe direction against a hard limit.
/// </para>
/// </summary>
public sealed class OmdbCallBudget(IServiceScopeFactory scopeFactory, OmdbSettings settings, ILogger<OmdbCallBudget> logger) : IOmdbCallBudget
{
    /// <summary>The counter's provider name.</summary>
    public const string Provider = "omdb";

    // The UTC day each priority ran out on, or 0 when not known to be spent.
    // A local shortcut so a spent allowance costs no round trip per skipped call, the shared counter staying authoritative.
    // Keyed by day, so a stale value never suppresses calls past the UTC midnight renewal.
    private int _interactiveExhaustedDay;

    private int _backgroundExhaustedDay;

    /// <summary>
    /// How many of the day's calls <paramref name="priority"/> may reach:
    /// the whole allowance for interactive work, all but <see cref="OmdbSettings.InteractiveReserve"/> for batch work.
    /// </summary>
    public int Ceiling(OmdbCallPriority priority) => priority == OmdbCallPriority.Interactive
        ? settings.DailyCallBudget
        : settings.DailyCallBudget - settings.InteractiveReserve;

    public bool IsExhausted(OmdbCallPriority priority)
    {
        var today = UtcToday().DayNumber;
        // interactive running out implies background did, with its lower ceiling, but not the reverse
        return Volatile.Read(ref _interactiveExhaustedDay) == today
               || (priority == OmdbCallPriority.Background && Volatile.Read(ref _backgroundExhaustedDay) == today);
    }

    public async Task<bool> TryReserveAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default)
    {
        if (IsExhausted(priority)) return false;

        var today = UtcToday();
        await using var scope = scopeFactory.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IProviderQuotaRepository>();

        var reserved = await repository.TryConsumeAsync(Provider, today, Ceiling(priority), cancellationToken);
        if (!reserved)
        {
            MarkExhaustedLocally(priority, today);
            logger.LogInformation(
                "OMDb daily call budget reached for {Priority} work ({Ceiling} of {DailyCallBudget} calls); IMDb lookups resume at the next UTC day.",
                priority, Ceiling(priority), settings.DailyCallBudget);
        }

        return reserved;
    }

    public async Task MarkLimitReachedAsync(CancellationToken cancellationToken = default)
    {
        var today = UtcToday();
        MarkExhaustedLocally(OmdbCallPriority.Interactive, today);
        MarkExhaustedLocally(OmdbCallPriority.Background, today);

        await using var scope = scopeFactory.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IProviderQuotaRepository>();
        await repository.ExhaustAsync(Provider, today, settings.DailyCallBudget, cancellationToken);
    }

    public async Task<int> GetRemainingAsync(OmdbCallPriority priority, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(settings.ApiKey)) return 0; // without a key no call is made
        if (IsExhausted(priority)) return 0;

        await using var scope = scopeFactory.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IProviderQuotaRepository>();
        var used = await repository.GetUsedAsync(Provider, UtcToday(), cancellationToken);
        return Math.Max(0, Ceiling(priority) - used);
    }

    private void MarkExhaustedLocally(OmdbCallPriority priority, DateOnly day)
    {
        if (priority == OmdbCallPriority.Interactive)
        {
            Volatile.Write(ref _interactiveExhaustedDay, day.DayNumber);
        }
        else
        {
            Volatile.Write(ref _backgroundExhaustedDay, day.DayNumber);
        }
    }

    // UTC, matching OMDb's reset and every replica's key, where local time would split replicas across zones
    private static DateOnly UtcToday() => DateOnly.FromDateTime(DateTime.UtcNow);
}
