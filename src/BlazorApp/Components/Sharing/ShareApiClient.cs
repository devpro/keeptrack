using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Sharing;

/// <summary>
/// The owner side of sharing - issue, list and revoke directed share grants (<c>/api/shares</c>).
/// Registered with <c>AuthenticationTokenHandler</c> like every other authenticated API client.
/// </summary>
public sealed class ShareApiClient(HttpClient http)
{
    public async Task<List<ShareDto>> GetSharesAsync()
    {
        var result = await http.GetFromJsonAsync<List<ShareDto>>("/api/shares");
        return result ?? [];
    }

    public async Task<ShareDto> CreateShareAsync(CreateShareRequestDto request)
    {
        var response = await http.PostAsJsonAsync("/api/shares", request);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<ShareDto>())!;
    }

    public async Task DeleteShareAsync(string id) =>
        (await http.DeleteAsync($"/api/shares/{id}")).EnsureSuccessStatusCode();
}
