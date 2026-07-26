using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Account;

public sealed class UserPreferencesApiClient(HttpClient http)
{
    private const string ApiUserPreferences = "/api/user-preferences";

    public async Task<UserPreferencesDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<UserPreferencesDto>(ApiUserPreferences);
        return result ?? new UserPreferencesDto();
    }

    public async Task UpdateAsync(UserPreferencesDto dto)
    {
        (await http.PutAsJsonAsync(ApiUserPreferences, dto)).EnsureSuccessStatusCode();
    }
}
