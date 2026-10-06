using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Circuit-scoped cache of the caller's own <see cref="UserPreferencesDto"/> (registered <c>AddScoped</c>).
/// Several consumers on one page read preferences (every owned copy's <c>OwnedVersionFields</c>), and fetching independently would cost one HTTP request each.
/// It fetches once per circuit, and every consumer shares the same <see cref="Task{TResult}"/>.
/// <see cref="UpdateAsync"/> (called from Manage.razor) refreshes the cache at once, so a page navigated to afterwards sees the new value without a round trip.
/// </summary>
public sealed class UserPreferencesState(UserPreferencesApiClient api)
{
    private Task<UserPreferencesDto>? _cached;

    public Task<UserPreferencesDto> GetAsync()
    {
        return _cached ??= api.GetAsync();
    }

    public async Task UpdateAsync(UserPreferencesDto dto)
    {
        await api.UpdateAsync(dto);
        _cached = Task.FromResult(dto);
    }
}
