using System.Threading;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single gate every OMDb call passes through, enforcing the key's daily quota across replicas.
/// <para>
/// OMDb's free tier is 1000 calls a day and it answers an exhausted key with an HTTP 401 rather than data, so
/// "just keep calling and see" costs a whole pass of failures and blocks the *next* thing that genuinely
/// needed a call. Two consumers spend the key on the same 24h tick (the reference sync's IMDb backfill, then
/// the Explore catalogue backfill) and neither could previously see what the other had spent, so each was
/// capped by a hardcoded guess that had to assume the worst.
/// </para>
/// <para>
/// The count lives in MongoDB (<see cref="IProviderQuotaRepository"/>), not in this process: the bulk
/// consumers run under the reference-sync lease so only one replica spends in volume, but interactive
/// resolves land on whichever replica served the request, and an in-process counter would let every replica
/// spend the full allowance. Reservation happens *before* the HTTP call, so an over-count (a reserved call
/// that then fails) is possible while an under-count is not - the safe direction against a hard limit.
/// </para>
/// </summary>
public sealed class OmdbCallBudget(IServiceScopeFactory scopeFactory, OmdbSettings settings, ILogger<OmdbCallBudget> logger) : IOmdbCallBudget
{
    /// <summary>Counter name - one provider today, but the counter itself is provider-agnostic.</summary>
    public const string Provider = "omdb";

    // The UTC day number each priority is known to have run out on, or 0 for "not known to be spent". Purely
    // a local shortcut so an exhausted allowance costs no database round trip per skipped call - the shared
    // counter stays authoritative. Keying it by day is what makes a stale value harmless: it can never
    // suppress calls past the UTC midnight the allowance renews at, however long this process lives.
    private int _interactiveExhaustedDay;

    private int _backgroundExhaustedDay;

    /// <summary>
    /// How many of the day's calls <paramref name="priority"/> may reach - the full allowance for interactive
    /// work, everything but <see cref="OmdbSettings.InteractiveReserve"/> for batch work.
    /// </summary>
    public int Ceiling(OmdbCallPriority priority) => priority == OmdbCallPriority.Interactive
        ? settings.DailyCallBudget
        : settings.DailyCallBudget - settings.InteractiveReserve;

    public bool IsExhausted(OmdbCallPriority priority)
    {
        var today = UtcToday().DayNumber;
        // interactive running out implies background did too (it has the lower ceiling); the reverse doesn't hold
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
        if (string.IsNullOrEmpty(settings.ApiKey)) return 0; // no key: every call is a no-op anyway
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

    // UTC, matching both OMDb's own daily reset and the key every replica computes - a local-time day would
    // have replicas in different zones disagreeing about which counter they're spending.
    private static DateOnly UtcToday() => DateOnly.FromDateTime(DateTime.UtcNow);
}
