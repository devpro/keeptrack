using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.WatchNext;

public sealed class WatchNextApiClient(HttpClient http)
{
    public async Task<WatchNextDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<WatchNextDto>("/api/watch-next");
        return result ?? new WatchNextDto();
    }
}
