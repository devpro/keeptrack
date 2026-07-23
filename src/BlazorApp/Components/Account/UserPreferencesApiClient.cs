using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Account;

public sealed class UserPreferencesApiClient(HttpClient http)
{
    public async Task<UserPreferencesDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<UserPreferencesDto>("/api/user-preferences");
        return result ?? new UserPreferencesDto();
    }

    public async Task UpdateAsync(UserPreferencesDto dto) =>
        (await http.PutAsJsonAsync("/api/user-preferences", dto)).EnsureSuccessStatusCode();
}
