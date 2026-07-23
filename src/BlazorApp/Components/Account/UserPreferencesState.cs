using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Circuit-scoped cache of the caller's own <see cref="UserPreferencesDto"/> (registered <c>AddScoped</c>).
/// Preference checks now happen in more than one place per page (e.g. every owned copy's
/// <c>OwnedVersionFields</c> instance on a detail page), so each consumer fetching independently would fire
/// one HTTP request per instance; this fetches once per circuit and every consumer shares the same
/// in-flight/completed <see cref="Task{TResult}"/> instead. <see cref="UpdateAsync"/> (only called from
/// Manage.razor) refreshes the cache immediately, so a page navigated to afterward sees the new value
/// without a second round trip.
/// </summary>
public sealed class UserPreferencesState(UserPreferencesApiClient api)
{
    private Task<UserPreferencesDto>? _cached;

    public Task<UserPreferencesDto> GetAsync() => _cached ??= api.GetAsync();

    public async Task UpdateAsync(UserPreferencesDto dto)
    {
        await api.UpdateAsync(dto);
        _cached = Task.FromResult(dto);
    }
}
